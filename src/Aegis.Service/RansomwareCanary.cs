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
    private readonly Dictionary<string, string> _hashes = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _alerted = new(StringComparer.OrdinalIgnoreCase);
    private readonly string _manifestPath;
    private readonly object _gate = new();

    public RansomwareCanary(string root)
    {
        _manifestPath = Path.Combine(root, "canaries.json");
    }

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
            var targets = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads")
            }.Where(p => !string.IsNullOrWhiteSpace(p) && Directory.Exists(p)).Distinct(StringComparer.OrdinalIgnoreCase);

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
            foreach (var (path, hash) in manifest.Hashes) _hashes[path] = hash;
            foreach (var (path, hash) in manifest.Alerted) _alerted[path] = hash;
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            // Sin baseline fiable se recalcula, pero el servicio sigue arrancando.
            _hashes.Clear();
            _alerted.Clear();
        }
    }

    private void SaveManifest()
    {
        var manifest = new CanaryManifest { Hashes = _hashes, Alerted = _alerted };
        var temp = _manifestPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(manifest, JsonDefaults.Options));
        File.Move(temp, _manifestPath, true);
    }

    private static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private sealed class CanaryManifest
    {
        public Dictionary<string, string> Hashes { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> Alerted { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }
}
