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
        IntelFile? data;
        try
        {
            data = JsonSerializer.Deserialize<IntelFile>(File.ReadAllText(path), JsonDefaults.Options);
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            // Un archivo corrupto degrada a "sin inteligencia", no impide el arranque.
            return;
        }
        if (data is null) return;
        lock (_gate)
        {
            _hashes.Clear(); _domains.Clear(); _ips.Clear();
            foreach (var h in data.MaliciousSha256.Where(x => x?.Length == 64)) _hashes.Add(h!.ToLowerInvariant());
            foreach (var d in data.MaliciousDomains.Where(x => x?.Length > 3)) _domains.Add(d!.ToLowerInvariant());
            foreach (var i in data.MaliciousIps.Where(x => x?.Length > 6)) _ips.Add(NormalizeIp(i!));
        }
    }

    private static string NormalizeIp(string value)
    {
        var text = value.Trim();
        return System.Net.IPAddress.TryParse(text, out var ip) ? ip.ToString() : text.ToLowerInvariant();
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
        var value = NormalizeIp(ip);
        lock (_gate) return _ips.Contains(value);
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

    public static bool IsQuarantineSafe(string path, string? applicationDataDir = null)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path)) return false;
        var full = Path.GetFullPath(path);
        var separator = Path.DirectorySeparatorChar;
        // Comparar con separador evita rechazar C:\Windows-evil y permite excluir
        // el propio directorio de datos, donde viven key.bin y el manifiesto.
        if (ProtectedPrefixes.Any(p => full.StartsWith(p.TrimEnd(separator) + separator, StringComparison.OrdinalIgnoreCase)))
            return false;
        if (!string.IsNullOrWhiteSpace(applicationDataDir))
        {
            var app = Path.GetFullPath(applicationDataDir).TrimEnd(separator);
            if (full.StartsWith(app + separator, StringComparison.OrdinalIgnoreCase)) return false;
        }
        var root = Path.GetPathRoot(full);
        // Solo unidades locales: nunca cifrar/borrar ficheros de un share UNC.
        if (root is null || root.Length != 3 || root[1] != ':') return false;
        if (string.Equals(full, root, StringComparison.OrdinalIgnoreCase)) return false;
        return true;
    }
}
