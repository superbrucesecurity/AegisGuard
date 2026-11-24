using System.Collections.Concurrent;

namespace Aegis.Core;

/// <summary>
/// Reputación local en memoria construida con el historial de decisiones de la
/// sesión. No consulta listas remotas ni servicios externos; se reinicia con
/// el servicio y está acotada para no crecer sin límite.
/// </summary>
public sealed class LocalReputation
{
    private const int MaxEntries = 4096;
    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.OrdinalIgnoreCase);

    public int Count => _entries.Count;

    public double Get(string? key)
    {
        if (string.IsNullOrWhiteSpace(key)) return 0.5;
        return _entries.TryGetValue(key, out var entry) ? entry.Score : 0.5;
    }

    public void Record(string? key, bool malicious)
    {
        if (string.IsNullOrWhiteSpace(key)) return;
        if (_entries.Count >= MaxEntries && !_entries.ContainsKey(key)) return;

        _entries.AddOrUpdate(key,
            _ => new Entry
            {
                Score = malicious ? 0.1 : 0.7,
                Hits = 1,
                Malicious = malicious ? 1 : 0
            },
            (_, entry) =>
            {
                if (malicious) entry.Malicious++;
                else if (entry.Malicious > 0) entry.Malicious--;
                else entry.Hits++;

                entry.Score = entry.Malicious > 0
                    ? 0.1
                    : Math.Min(0.9, 0.5 + entry.Hits * 0.05);
                return entry;
            });
    }

    private sealed class Entry
    {
        public double Score { get; set; }
        public int Hits { get; set; }
        public int Malicious { get; set; }
    }
}
