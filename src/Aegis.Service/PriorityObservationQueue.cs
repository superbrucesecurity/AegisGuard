using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Threading.Channels;
using Aegis.Core;

namespace Aegis.Service;

/// <summary>
/// Cola de observaciones con dos prioridades, coalescencia y métricas reales.
/// Los callbacks de los sensores solo llaman a <see cref="TryEnqueue"/>: nunca
/// ejecutan análisis ni esperan al consumidor.
/// </summary>
public sealed class PriorityObservationQueue
{
    private readonly Channel<Observation> _critical;
    private readonly Channel<Observation> _normal;
    private readonly ConcurrentDictionary<string, long> _lastSeen = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _writeGate = new();
    private readonly TimeSpan _coalesceWindow;
    private long _enqueued;
    private long _droppedCritical;
    private long _droppedNormal;
    private long _coalesced;
    private long _oldestTicks = long.MaxValue;

    public PriorityObservationQueue(int criticalCapacity = 512, int normalCapacity = 2000, int coalesceMilliseconds = 500)
    {
        CriticalCapacity = criticalCapacity;
        NormalCapacity = normalCapacity;
        _coalesceWindow = TimeSpan.FromMilliseconds(coalesceMilliseconds);
        _critical = Channel.CreateBounded<Observation>(new BoundedChannelOptions(criticalCapacity)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true
        });
        _normal = Channel.CreateBounded<Observation>(new BoundedChannelOptions(normalCapacity)
        {
            // Backpressure: el productor nunca espera; si está llena se contabiliza
            // el descarte y se eleva el estado de degradación.
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true
        });
    }

    public int CriticalCapacity { get; }
    public int NormalCapacity { get; }
    public long Enqueued => Interlocked.Read(ref _enqueued);
    public long DroppedCritical => Interlocked.Read(ref _droppedCritical);
    public long DroppedNormal => Interlocked.Read(ref _droppedNormal);
    public long Dropped => DroppedCritical + DroppedNormal;
    public long Coalesced => Interlocked.Read(ref _coalesced);
    public int CriticalDepth => _critical.Reader.Count;
    public int NormalDepth => _normal.Reader.Count;
    public bool Saturated => Dropped > 0 || CriticalDepth >= CriticalCapacity || NormalDepth >= NormalCapacity;

    public double OldestQueuedSeconds
    {
        get
        {
            var ticks = Interlocked.Read(ref _oldestTicks);
            return ticks == long.MaxValue ? 0 : Math.Max(0, (DateTime.UtcNow.Ticks - ticks) / (double)TimeSpan.TicksPerSecond);
        }
    }

    public static bool IsCritical(Observation observation) =>
        observation.BehaviorFlags.Any(f => f is
            "ransomware_canary_modified" or "canary_manifest_tampered" or "c2_beacon" or "pid_reuse_suspected") ||
        observation.Source.StartsWith("canary", StringComparison.OrdinalIgnoreCase) ||
        observation.Kind is EventKind.ManualScan or EventKind.PersistenceChanged;

    /// <summary>Encola sin bloquear. Devuelve false si no se encoló (duplicado o descarte).</summary>
    public bool TryEnqueue(Observation observation) => TryEnqueue(observation, out _);

    /// <summary>
    /// Encola sin bloquear y distingue entre duplicado coalescionado y pérdida
    /// real. Solo el descarte debe elevar el estado a degradado.
    /// </summary>
    public bool TryEnqueue(Observation observation, out bool coalesced)
    {
        ArgumentNullException.ThrowIfNull(observation);
        coalesced = false;
        var now = DateTime.UtcNow.Ticks;
        var key = string.Concat(observation.Kind, "|", observation.Subject, "|",
            observation.ProcessId ?? string.Empty, "|", observation.RemoteAddress ?? string.Empty);
        // El primer evento de una clave nunca es duplicado: GetOrAdd(key, now)
        // insertaría la marca antes de comparar y descartaría ese primer evento.
        if (_lastSeen.TryGetValue(key, out var previous) && now - previous < _coalesceWindow.Ticks)
        {
            Interlocked.Increment(ref _coalesced);
            coalesced = true;
            return false;
        }
        _lastSeen[key] = now;
        // Evitar que el diccionario de coalescencia crezca sin límite.
        if (_lastSeen.Count > 20_000)
            foreach (var entry in _lastSeen.Where(x => now - x.Value > TimeSpan.FromMinutes(5).Ticks))
                _lastSeen.TryRemove(entry.Key, out _);

        var critical = IsCritical(observation);
        var target = critical ? _critical : _normal;
        lock (_writeGate)
        {
            // DropOldest devuelve true incluso cuando descarta: hay que contar
            // ese descarte antes de escribir para no ocultar pérdida real.
            if (critical && target.Reader.Count >= CriticalCapacity)
                Interlocked.Increment(ref _droppedCritical);
            if (!target.Writer.TryWrite(observation))
            {
                if (critical) Interlocked.Increment(ref _droppedCritical);
                else Interlocked.Increment(ref _droppedNormal);
                return false;
            }
        }
        Interlocked.Increment(ref _enqueued);
        NoteEnqueue(now);
        return true;
    }

    public void Complete()
    {
        _critical.Writer.TryComplete();
        _normal.Writer.TryComplete();
    }

    public async IAsyncEnumerable<Observation> ReadAllAsync([EnumeratorCancellation] CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            // Drenar primero la cola crítica: ante saturación, las alertas de
            // ransomware y manipulación pasan antes que el ruido de red.
            if (_critical.Reader.TryRead(out var critical))
            {
                yield return critical;
                NoteDequeuedIfEmpty();
                continue;
            }
            if (_normal.Reader.TryRead(out var normal))
            {
                yield return normal;
                NoteDequeuedIfEmpty();
                continue;
            }

            var criticalWait = _critical.Reader.WaitToReadAsync(ct).AsTask();
            var normalWait = _normal.Reader.WaitToReadAsync(ct).AsTask();
            var completed = await Task.WhenAny(criticalWait, normalWait).ConfigureAwait(false);
            if (completed == criticalWait && criticalWait.Result && _critical.Reader.TryRead(out critical))
            {
                yield return critical;
                NoteDequeuedIfEmpty();
            }
            else if (normalWait.Result && _normal.Reader.TryRead(out normal))
            {
                // Puede haber llegado una alerta crítica mientras esperábamos.
                if (_critical.Reader.TryRead(out critical)) yield return critical;
                else yield return normal;
                NoteDequeuedIfEmpty();
            }
        }
    }

    private void NoteEnqueue(long ticks)
    {
        while (true)
        {
            var current = Interlocked.Read(ref _oldestTicks);
            if (ticks >= current || Interlocked.CompareExchange(ref _oldestTicks, ticks, current) == current) return;
        }
    }

    private void NoteDequeuedIfEmpty()
    {
        if (CriticalDepth == 0 && NormalDepth == 0)
            Interlocked.Exchange(ref _oldestTicks, long.MaxValue);
    }
}
