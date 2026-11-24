using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Aegis.Core;

/// <summary>
/// Reputación local persistida en el directorio de datos del producto. No
/// consulta servicios remotos. La primera decisión adversaria solo reduce la
/// reputación a un valor bajo; hace falta corroboración para considerarla muy
/// baja y evitar un bucle de realimentación. Un fichero corrupto se descarta.
/// </summary>
public sealed class LocalReputation
{
    private const int MaxEntries = 4096;
    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.OrdinalIgnoreCase);
    private readonly string? _storePath;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private int _dirty;

    public LocalReputation(string? storePath = null)
    {
        if (!string.IsNullOrWhiteSpace(storePath))
        {
            _storePath = Path.GetFullPath(storePath);
            Load();
        }
    }

    public int Count => _entries.Count;
    public string? StorePath => _storePath;

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
                Score = malicious ? 0.35 : 0.7,
                Hits = malicious ? 0 : 1,
                Malicious = malicious ? 1 : 0
            },
            (_, entry) =>
            {
                if (malicious) entry.Malicious = Math.Min(100, entry.Malicious + 1);
                else if (entry.Malicious > 0) entry.Malicious--;
                else entry.Hits = Math.Min(100, entry.Hits + 1);

                entry.Score = entry.Malicious switch
                {
                    >= 2 => 0.1,
                    1 => 0.35,
                    _ => Math.Min(0.9, 0.5 + entry.Hits * 0.05)
                };
                return entry;
            });
        Interlocked.Exchange(ref _dirty, 1);
    }

    /// <summary>Persiste de forma atómica solo si hubo cambios desde la última guardada.</summary>
    public async Task SaveAsync(CancellationToken ct = default)
    {
        if (_storePath is null || Volatile.Read(ref _dirty) == 0) return;

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (Volatile.Read(ref _dirty) == 0) return;
            Interlocked.Exchange(ref _dirty, 0);
            var entries = _entries.Select(x => new StoredEntry
            {
                Key = x.Key,
                Score = x.Value.Score,
                Hits = x.Value.Hits,
                Malicious = x.Value.Malicious
            }).OrderBy(x => x.Key, StringComparer.Ordinal).ToList();

            var canonical = Canonical(entries);
            var file = new ReputationFile
            {
                Entries = entries,
                Checksum = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)))
            };
            var directory = Path.GetDirectoryName(_storePath);
            if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);
            var temp = _storePath + ".tmp";
            await File.WriteAllTextAsync(temp, JsonSerializer.Serialize(file), ct).ConfigureAwait(false);
            File.Move(temp, _storePath, overwrite: true);
        }
        catch
        {
            Interlocked.Exchange(ref _dirty, 1);
            throw;
        }
        finally
        {
            _gate.Release();
        }
    }

    private void Load()
    {
        try
        {
            if (!File.Exists(_storePath!)) return;
            var file = JsonSerializer.Deserialize<ReputationFile>(File.ReadAllText(_storePath!));
            if (file?.Entries is null) return;
            var entries = file.Entries
                .Where(e => !string.IsNullOrWhiteSpace(e.Key))
                .OrderBy(e => e.Key, StringComparer.Ordinal)
                .ToList();
            var expected = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Canonical(entries))));
            if (!string.Equals(expected, file.Checksum, StringComparison.OrdinalIgnoreCase)) return;

            foreach (var entry in entries.Take(MaxEntries))
            {
                _entries[entry.Key] = new Entry
                {
                    Score = Math.Clamp(entry.Score, 0.1, 0.9),
                    Hits = Math.Clamp(entry.Hits, 0, 100),
                    Malicious = Math.Clamp(entry.Malicious, 0, 100)
                };
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or FormatException)
        {
            // Fichero corrupto: se ignora y se reconstruirá con nuevas decisiones.
        }
    }

    private static string Canonical(IReadOnlyList<StoredEntry> entries) =>
        JsonSerializer.Serialize(entries.Select(e => new
        {
            e.Key,
            e.Score,
            e.Hits,
            e.Malicious
        }));

    private sealed class Entry
    {
        public double Score { get; set; }
        public int Hits { get; set; }
        public int Malicious { get; set; }
    }

    private sealed class ReputationFile
    {
        [JsonPropertyName("entries")] public List<StoredEntry> Entries { get; set; } = [];
        [JsonPropertyName("checksum")] public string Checksum { get; set; } = string.Empty;
    }

    private sealed class StoredEntry
    {
        [JsonPropertyName("key")] public string Key { get; set; } = string.Empty;
        [JsonPropertyName("score")] public double Score { get; set; }
        [JsonPropertyName("hits")] public int Hits { get; set; }
        [JsonPropertyName("malicious")] public int Malicious { get; set; }
    }
}
