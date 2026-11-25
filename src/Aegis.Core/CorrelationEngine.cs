namespace Aegis.Core;

/// <summary>
/// Cotas del correlacionador. Toda la memoria es local al proceso y se pierde
/// al reiniciar: no se lee `events.jsonl` ni se escribe estado persistente.
/// </summary>
public sealed class CorrelationOptions
{
    public TimeSpan MaxWindow { get; init; } = TimeSpan.FromSeconds(300);
    public TimeSpan Ttl { get; init; } = TimeSpan.FromMinutes(10);
    public int MaxEventsPerKey { get; init; } = 6;
    public int MaxKeys { get; init; } = 1024;
    public int MaxFiredKeys { get; init; } = 2048;
    public int MaxMatchesPerObservation { get; init; } = 2;
    public double WeightPerMatch { get; init; } = 12;
    public double MaxCorrelationScorePerObservation { get; init; } = 24;
}

/// <summary>
/// Correlación temporal acotada entre eventos ya observados. Sólo dos reglas
/// deterministas; no crea reglas de detección, no inventa PID y nunca marca un
/// indicio como verificado. Admite eventos desordenados por prioridad de cola:
/// compara marcas de tiempo de los eventos, no orden de llegada.
/// </summary>
public sealed class CorrelationEngine
{
    public const string ProcessNetworkRule = "CORR-SUSPICIOUS-PROCESS-NETWORK";
    public const string ProcessPersistenceRule = "CORR-SUSPICIOUS-PROCESS-PERSISTENCE";

    private static readonly TimeSpan NetworkWindow = TimeSpan.FromSeconds(120);
    private static readonly TimeSpan PersistenceWindow = TimeSpan.FromSeconds(300);

    private readonly CorrelationOptions _options;
    private readonly Func<DateTimeOffset> _clock;
    private readonly object _sync = new();
    private readonly Dictionary<string, List<BufferedEvent>> _buckets = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTimeOffset> _fired = new(StringComparer.Ordinal);

    private sealed class BufferedEvent
    {
        public required Observation Observation { get; init; }
        public required DateTimeOffset SeenAt { get; init; }
    }

    public CorrelationEngine(CorrelationOptions? options = null, Func<DateTimeOffset>? clock = null)
    {
        _options = options ?? new CorrelationOptions();
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    public int KeyCount
    {
        get { lock (_sync) { Prune(_clock()); return _buckets.Count; } }
    }

    public int BufferedEvents
    {
        get { lock (_sync) { Prune(_clock()); return _buckets.Values.Sum(b => b.Count); } }
    }

    /// <summary>
    /// Registra una observación y devuelve las correlaciones que provocó. Una
    /// regla dispara como máximo una vez por ancla para que diez conexiones no
    /// inflen el score.
    /// </summary>
    public IReadOnlyList<CorrelationMatch> Observe(Observation observation)
    {
        ArgumentNullException.ThrowIfNull(observation);
        var pid = NormalizePid(observation.ProcessId);
        if (string.IsNullOrEmpty(pid)) return [];

        var now = _clock();
        lock (_sync)
        {
            Prune(now);
            if (!_buckets.TryGetValue(pid, out var bucket))
            {
                bucket = [];
                _buckets[pid] = bucket;
            }

            var results = new List<CorrelationMatch>();
            if (IsAnchor(observation))
            {
                // El disparador pudo llegar antes porque la cola prioriza
                // eventos críticos: se comparan marcas de tiempo, no llegada.
                // Una sola ancla por regla: se toma el disparador más cercano.
                var triggers = bucket.Where(x => TriggerRule(x.Observation) is not null)
                    .GroupBy(x => TriggerRule(x.Observation)!);
                foreach (var group in triggers)
                {
                    var best = group.Select(x => x.Observation)
                        .Where(t => t.Timestamp >= observation.Timestamp &&
                                    t.Timestamp - observation.Timestamp <= RuleWindow(group.Key))
                        .OrderBy(t => t.Timestamp)
                        .FirstOrDefault();
                    if (best is not null) TryMatch(results, group.Key, observation, best, pid, now);
                }
            }
            else if (TriggerRule(observation) is { } ruleId)
            {
                // Ante reutilización de PID se toma el ancla más reciente que
                // preceda al disparador, no todas las anclas acumuladas.
                var best = bucket.Where(x => IsAnchor(x.Observation))
                    .Select(x => x.Observation)
                    .Where(a => a.Timestamp <= observation.Timestamp &&
                                observation.Timestamp - a.Timestamp <= RuleWindow(ruleId))
                    .OrderByDescending(a => a.Timestamp)
                    .FirstOrDefault();
                if (best is not null) TryMatch(results, ruleId, best, observation, pid, now);
            }

            AddBounded(bucket, observation, now);
            return results;
        }
    }

    public void Reset()
    {
        lock (_sync)
        {
            _buckets.Clear();
            _fired.Clear();
        }
    }

    private void TryMatch(
        List<CorrelationMatch> results,
        string ruleId,
        Observation anchor,
        Observation trigger,
        string pid,
        DateTimeOffset now)
    {
        if (results.Count >= _options.MaxMatchesPerObservation) return;
        if (results.Sum(x => x.Weight) + _options.WeightPerMatch > _options.MaxCorrelationScorePerObservation) return;

        var window = RuleWindow(ruleId);
        var delta = trigger.Timestamp - anchor.Timestamp;
        if (delta < TimeSpan.Zero || delta > window) return;

        var key = ruleId + "|" + anchor.Id;
        if (_fired.ContainsKey(key)) return;
        _fired[key] = now;

        results.Add(new CorrelationMatch
        {
            RuleId = ruleId,
            Reason = ruleId == ProcessPersistenceRule
                ? "proceso con señales sospechosas seguido de persistencia en el registro"
                : "proceso con señales sospechosas seguido de red pública o comportamiento C2",
            Weight = _options.WeightPerMatch,
            Evidence =
            [
                EvidenceOf(anchor, pid, true),
                EvidenceOf(trigger, pid, false)
            ]
        });
    }

    private CorrelationEvidence EvidenceOf(Observation observation, string pid, bool anchor)
    {
        var details = new List<string> { "pid=" + pid };
        if (anchor)
        {
            foreach (var flag in observation.BehaviorFlags
                         .Where(f => f is "temp_execution" or "unusual_parent")
                         .Distinct(StringComparer.OrdinalIgnoreCase))
                details.Add("flag=" + flag);
        }
        else
        {
            if (observation.Kind == EventKind.NetworkConnection && TelemetryAddress.IsPublicIp(observation.RemoteAddress))
                details.Add("remote=" + observation.RemoteAddress!.Trim());
            if (observation.Kind == EventKind.DnsQuery && !string.IsNullOrWhiteSpace(observation.Subject))
                details.Add("domain=" + observation.Subject);
            foreach (var flag in observation.BehaviorFlags
                         .Where(f => f is "c2_beacon" or "persistence_registry")
                         .Distinct(StringComparer.OrdinalIgnoreCase))
                details.Add("flag=" + flag);
        }

        return new CorrelationEvidence
        {
            ObservationId = observation.Id,
            Timestamp = observation.Timestamp,
            Kind = observation.Kind,
            Subject = Clip(observation.Subject, 200),
            Details = details
        };
    }

    private void AddBounded(List<BufferedEvent> bucket, Observation observation, DateTimeOffset now)
    {
        if (bucket.Count >= _options.MaxEventsPerKey)
        {
            var oldest = bucket.OrderBy(x => x.SeenAt).ThenBy(x => x.Observation.Timestamp).First();
            bucket.Remove(oldest);
        }
        bucket.Add(new BufferedEvent { Observation = observation, SeenAt = now });
    }

    private void Prune(DateTimeOffset now)
    {
        foreach (var pair in _buckets.ToList())
        {
            var kept = pair.Value.Where(x => now - x.SeenAt <= _options.Ttl).ToList();
            if (kept.Count == 0) _buckets.Remove(pair.Key);
            else if (kept.Count != pair.Value.Count)
            {
                pair.Value.Clear();
                pair.Value.AddRange(kept);
            }
        }

        foreach (var key in _fired.Where(x => now - x.Value > _options.Ttl).Select(x => x.Key).ToList())
            _fired.Remove(key);

        while (_buckets.Count > _options.MaxKeys)
        {
            var victim = _buckets.OrderBy(x => x.Value.Min(e => e.SeenAt))
                .ThenBy(x => x.Key, StringComparer.Ordinal).First();
            _buckets.Remove(victim.Key);
        }

        while (_fired.Count > _options.MaxFiredKeys)
        {
            var victim = _fired.OrderBy(x => x.Value).ThenBy(x => x.Key, StringComparer.Ordinal).First();
            _fired.Remove(victim.Key);
        }
    }

    private TimeSpan RuleWindow(string ruleId)
    {
        var window = ruleId == ProcessPersistenceRule ? PersistenceWindow : NetworkWindow;
        return window > _options.MaxWindow ? _options.MaxWindow : window;
    }

    private static bool IsAnchor(Observation o) =>
        o.Kind == EventKind.ProcessStarted &&
        !string.IsNullOrWhiteSpace(o.ProcessId) &&
        o.BehaviorFlags.Any(f => f is "temp_execution" or "unusual_parent");

    /// <summary>Devuelve la regla aplicable al disparador, o null si no hay evidencia real.</summary>
    private static string? TriggerRule(Observation o)
    {
        if (string.IsNullOrWhiteSpace(o.ProcessId)) return null;
        switch (o.Kind)
        {
            case EventKind.NetworkConnection when
                o.BehaviorFlags.Any(f => f == "c2_beacon") || TelemetryAddress.IsPublicIp(o.RemoteAddress):
                return ProcessNetworkRule;
            case EventKind.DnsQuery when o.BehaviorFlags.Any(f => f == "c2_beacon"):
                return ProcessNetworkRule;
            case EventKind.PersistenceChanged when o.BehaviorFlags.Any(f => f == "persistence_registry"):
                return ProcessPersistenceRule;
            default:
                return null;
        }
    }

    private static string NormalizePid(string? pid) =>
        string.IsNullOrWhiteSpace(pid) ? string.Empty : pid.Trim();

    private static string Clip(string value, int max) =>
        string.IsNullOrEmpty(value) ? string.Empty : value.Length <= max ? value : value[..max] + "…";
}
