using System.Text.Json;
using Aegis.Core;

namespace Aegis.Service;

public sealed class EventStore
{
    private readonly string _observationsPath;
    private readonly string _threatsPath;
    private readonly int _maxMemory;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly List<Observation> _observations = [];
    private readonly List<ThreatRecord> _threats = [];

    public EventStore(string root, int maxMemory = 5000)
    {
        _observationsPath = Path.Combine(root, "events.jsonl");
        _threatsPath = Path.Combine(root, "threats.jsonl");
        _maxMemory = maxMemory;
    }

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_observationsPath)!);
        await LoadAsync(_observationsPath, _observations).ConfigureAwait(false);
        await LoadAsync(_threatsPath, _threats).ConfigureAwait(false);
    }

    public IReadOnlyList<Observation> Observations
    {
        get { lock (_gate) return [.. _observations]; }
    }

    public IReadOnlyList<ThreatRecord> Threats
    {
        get { lock (_gate) return [.. _threats]; }
    }

    public async Task AppendAsync(Observation observation)
    {
        lock (_gate)
        {
            _observations.Add(observation);
            Trim(_observations);
        }
        await AppendLineAsync(_observationsPath, JsonSerializer.Serialize(observation, JsonDefaults.Options)).ConfigureAwait(false);
    }

    public async Task AppendAsync(ThreatRecord threat)
    {
        lock (_gate)
        {
            _threats.Add(threat);
            Trim(_threats);
        }
        await AppendLineAsync(_threatsPath, JsonSerializer.Serialize(threat, JsonDefaults.Options)).ConfigureAwait(false);
    }

    public async Task MarkRemediatedAsync(string threatId, string detail)
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            var threat = _threats.FirstOrDefault(x => x.Id.Equals(threatId, StringComparison.OrdinalIgnoreCase));
            if (threat is null) return;
            threat.Remediated = true;
            threat.RemediationDetail = detail;
            // Instantánea bajo el mismo candado: si se libera antes de escribir,
            // un AppendAsync concurrente puede perderse al truncar el fichero.
            var snapshot = _threats.Select(x => JsonSerializer.Serialize(x, JsonDefaults.Options)).ToList();
            await FileGate.WaitAsync().ConfigureAwait(false);
            try
            {
                await File.WriteAllTextAsync(_threatsPath, string.Join(Environment.NewLine, snapshot)).ConfigureAwait(false);
            }
            finally { FileGate.Release(); }
        }
        finally { _gate.Release(); }
    }

    private static async Task LoadAsync<T>(string path, List<T> target)
    {
        if (!File.Exists(path)) return;
        string[] lines;
        try
        {
            lines = await File.ReadAllLinesAsync(path).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return;
        }
        foreach (var line in lines)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            try
            {
                if (JsonSerializer.Deserialize<T>(line, JsonDefaults.Options) is { } item)
                    target.Add(item);
            }
            catch (JsonException)
            {
                // Una línea truncada por un corte de luz no descarta el resto.
            }
        }
        if (target.Count > 5000)
        {
            var keep = target.Skip(target.Count - 5000).ToList();
            target.Clear();
            target.AddRange(keep);
        }
    }

    private void Trim<T>(List<T> list)
    {
        if (list.Count > _maxMemory) list.RemoveRange(0, list.Count - _maxMemory);
    }

    private static readonly SemaphoreSlim FileGate = new(1, 1);
    private static async Task AppendLineAsync(string path, string line)
    {
        await FileGate.WaitAsync().ConfigureAwait(false);
        try
        {
            await File.AppendAllTextAsync(path, line + Environment.NewLine).ConfigureAwait(false);
        }
        finally { FileGate.Release(); }
    }
}
