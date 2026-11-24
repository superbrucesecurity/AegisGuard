using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Aegis.Core;

namespace Aegis.Service;

/// <summary>
/// Archivos señuelo ocultos en directorios de usuario. Un cambio (o borrado)
/// en su contenido es un indicador fuerte de cifrado masivo/ransomware.
/// El baseline se persiste para detectar alteraciones mientras el servicio está apagado.
/// </summary>
public sealed class RansomwareCanary
{
    private const int ManifestVersion = 2;
    private const string KeyLabel = "AegisGuard.Canary.v1";
    private readonly Dictionary<string, string> _hashes = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _alerted = new(StringComparer.OrdinalIgnoreCase);
    private readonly string _manifestPath;
    private readonly IReadOnlyList<string>? _targets;
    private readonly object _gate = new();
    private volatile bool _manifestTampered;

    public RansomwareCanary(string root, IEnumerable<string>? targets = null)
    {
        _manifestPath = Path.Combine(root, "canaries.json");
        _targets = targets?.ToList();
    }

    public string ManifestPath => _manifestPath;

    /// <summary>
    /// El manifiesto no coincide con su HMAC local. No implica que un atacante
    /// haya eludido la protección: solo que la baseline fue editada o corrupta.
    /// </summary>
    public bool ManifestTampered => _manifestTampered;

    public string IntegrityStatus { get; private set; } = "new";

    public IReadOnlyList<string> Paths
    {
        get { lock (_gate) return _hashes.Keys.ToList(); }
    }

    public void Initialize()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_manifestPath)!);
        lock (_gate)
        {
            LoadManifest();
            var targets = (_targets ?? new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads")
            }).Where(p => !string.IsNullOrWhiteSpace(p) && Directory.Exists(p)).Distinct(StringComparer.OrdinalIgnoreCase);

            foreach (var target in targets)
            {
                var name = Path.Combine(target, $".aegis-canary-{Environment.MachineName.ToLowerInvariant()}.txt");
                if (!_hashes.ContainsKey(name))
                {
                    if (!File.Exists(name))
                    {
                        var content = $"AEGIS Guard canary. Do not modify. {Guid.NewGuid():N}{Environment.NewLine}";
                        File.WriteAllText(name, content, Encoding.UTF8);
                        LocalFileAcl.Restrict(name);
                        File.SetAttributes(name, FileAttributes.Hidden | FileAttributes.System | FileAttributes.ReadOnly);
                    }
                    // Baseline nuevo: no se crea uno nuevo si ya existía en el
                    // manifiesto, para conservar evidencia de alteración en reposo.
                    _hashes[name] = Hash(File.ReadAllBytes(name));
                }
            }
            SaveManifest();
        }
    }

    public bool IsCanary(string path)
    {
        lock (_gate) return _hashes.ContainsKey(path);
    }

    public bool WasModified(string path)
    {
        lock (_gate)
        {
            if (!_hashes.TryGetValue(path, out var expected)) return false;
            string current;
            if (!File.Exists(path))
            {
                current = "<missing>";
            }
            else
            {
                try { current = Hash(File.ReadAllBytes(path)); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { current = "<unreadable>"; }
            }
            if (string.Equals(current, expected, StringComparison.OrdinalIgnoreCase)) return false;
            // Alertar una sola vez por cambio; el watcher y el bucle de sondeo
            // comparten este estado para no llenar el canal con duplicados.
            if (_alerted.TryGetValue(path, out var reported) &&
                string.Equals(reported, current, StringComparison.OrdinalIgnoreCase)) return false;
            _alerted[path] = current;
            SaveManifest();
            return true;
        }
    }

    private void LoadManifest()
    {
        if (!File.Exists(_manifestPath)) return;
        try
        {
            var manifest = JsonSerializer.Deserialize<CanaryManifest>(File.ReadAllText(_manifestPath), JsonDefaults.Options);
            if (manifest is null) return;
            IntegrityStatus = Verify(manifest) ? "ok" : "invalid";
            if (IntegrityStatus == "invalid") _manifestTampered = true;
            foreach (var (path, hash) in manifest.Hashes) _hashes[path] = hash;
            foreach (var (path, hash) in manifest.Alerted) _alerted[path] = hash;
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException or FormatException)
        {
            // Sin baseline fiable se recalcula, pero el servicio sigue arrancando.
            _hashes.Clear();
            _alerted.Clear();
            IntegrityStatus = "invalid";
            _manifestTampered = true;
        }
    }

    private static bool Verify(CanaryManifest manifest)
    {
        // Versiones anteriores no tenían firma: se migran una sola vez y se
        // firman al guardar. Un manifiesto con versión 2 y firma ausente o
        // distinta se considera alterado.
        if (manifest.Version is null or < ManifestVersion) return true;
        if (string.IsNullOrWhiteSpace(manifest.Signature)) return false;
        try
        {
            var expected = Convert.FromHexString(Sign(manifest));
            var actual = Convert.FromHexString(manifest.Signature);
            return CryptographicOperations.FixedTimeEquals(expected, actual);
        }
        catch (FormatException) { return false; }
    }

    private static string Sign(CanaryManifest manifest)
    {
        var canonical = new
        {
            version = ManifestVersion,
            hashes = manifest.Hashes.OrderBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(x => x.Key, x => x.Value, StringComparer.OrdinalIgnoreCase),
            alerted = manifest.Alerted.OrderBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(x => x.Key, x => x.Value, StringComparer.OrdinalIgnoreCase)
        };
        return Convert.ToHexString(HMACSHA256.HashData(ManifestKey(),
            Encoding.UTF8.GetBytes(JsonSerializer.Serialize(canonical, JsonDefaults.Options)))).ToLowerInvariant();
    }

    private static byte[] ManifestKey()
    {
        var label = Encoding.UTF8.GetBytes(KeyLabel);
        // DPAPI liga la clave al usuario del servicio. No resiste a un proceso
        // con los mismos privilegios: detecta edición casual o corrupción, no
        // sustituye a un control de integridad en kernel.
        return SHA256.HashData(OperatingSystem.IsWindows()
            ? ProtectedData.Protect(label, null, DataProtectionScope.CurrentUser)
            : label);
    }

    private void SaveManifest()
    {
        var manifest = new CanaryManifest
        {
            Version = ManifestVersion,
            Hashes = _hashes,
            Alerted = _alerted
        };
        manifest.Signature = Sign(manifest);
        var temp = _manifestPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(manifest, JsonDefaults.Options));
        File.Move(temp, _manifestPath, true);
        if (!_manifestTampered) IntegrityStatus = "ok";
    }

    private static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private sealed class CanaryManifest
    {
        // Sin inicializador: ausencia = manifiesto heredado no firmado.
        public int? Version { get; set; }
        public string Signature { get; set; } = string.Empty;
        public Dictionary<string, string> Hashes { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> Alerted { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }
}
