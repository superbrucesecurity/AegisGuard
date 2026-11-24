using System.Text.Json;
using System.Text.Json.Serialization;

namespace Aegis.Core;

public sealed class ThreatIntel
{
    private readonly HashSet<string> _hashes = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _domains = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _ips = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    public int HashCount { get { lock (_gate) return _hashes.Count; } }
    public int DomainCount { get { lock (_gate) return _domains.Count; } }
    public int IpCount { get { lock (_gate) return _ips.Count; } }

    public void Load(string path)
    {
        if (!File.Exists(path)) return;
        var data = JsonSerializer.Deserialize<IntelFile>(File.ReadAllText(path), JsonDefaults.Options);
        if (data is null) return;
        lock (_gate)
        {
            _hashes.Clear(); _domains.Clear(); _ips.Clear();
            foreach (var h in data.MaliciousSha256.Where(x => x.Length == 64)) _hashes.Add(h.ToLowerInvariant());
            foreach (var d in data.MaliciousDomains.Where(x => x.Length > 3)) _domains.Add(d.ToLowerInvariant());
            foreach (var i in data.MaliciousIps.Where(x => x.Length > 6)) _ips.Add(i.ToLowerInvariant());
        }
    }

    public bool IsMaliciousHash(string? hash)
    {
        if (string.IsNullOrWhiteSpace(hash)) return false;
        lock (_gate) return _hashes.Contains(hash);
    }

    public bool IsMaliciousDomain(string? domain)
    {
        if (string.IsNullOrWhiteSpace(domain)) return false;
        var value = domain.Trim().ToLowerInvariant();
        lock (_gate) return _domains.Any(d => value.Equals(d, StringComparison.OrdinalIgnoreCase) || value.EndsWith("." + d, StringComparison.OrdinalIgnoreCase));
    }

    public bool IsMaliciousIp(string? ip)
    {
        if (string.IsNullOrWhiteSpace(ip)) return false;
        lock (_gate) return _ips.Contains(ip.Trim());
    }

    public HashSet<string> SnapshotHashes()
    {
        lock (_gate) return new HashSet<string>(_hashes, StringComparer.OrdinalIgnoreCase);
    }

    private sealed class IntelFile
    {
        [JsonPropertyName("maliciousSha256")] public List<string> MaliciousSha256 { get; set; } = [];
        [JsonPropertyName("maliciousDomains")] public List<string> MaliciousDomains { get; set; } = [];
        [JsonPropertyName("maliciousIps")] public List<string> MaliciousIps { get; set; } = [];
    }
}

public static class PathPolicy
{
    private static readonly string[] ProtectedPrefixes =
    [
        @"C:\Windows", @"C:\Program Files", @"C:\Program Files (x86)", @"C:\ProgramData\Microsoft",
        @"C:\$Recycle.Bin", @"C:\System Volume Information"
    ];

    public static bool IsQuarantineSafe(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path)) return false;
        var full = Path.GetFullPath(path);
        if (ProtectedPrefixes.Any(p => full.StartsWith(p, StringComparison.OrdinalIgnoreCase))) return false;
        var root = Path.GetPathRoot(full);
        if (string.Equals(full, root, StringComparison.OrdinalIgnoreCase)) return false;
        return true;
    }
}
