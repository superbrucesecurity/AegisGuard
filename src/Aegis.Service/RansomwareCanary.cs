using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Aegis.Core;

namespace Aegis.Service;

/// <summary>
/// Archivos señuelo ocultos en directorios de usuario. Un cambio (o borrado)
/// en su contenido es un indicador fuerte de cifrado masivo/ransomware.
/// El baseline se persiste con HMAC cuya clave aleatoria se protege con DPAPI
/// y se reutiliza entre arranques; un manifiesto inválido nunca se acepta como
/// baseline fiable.
/// </summary>
public sealed class RansomwareCanary : IDisposable
{
    private const int ManifestVersion = 2;
    private const int KeyVersion = 1;
    private const string KeyLabel = "AegisGuard.Canary.Key.v1";
    private readonly Dictionary<string, string> _hashes = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _alerted = new(StringComparer.OrdinalIgnoreCase);
    private readonly string _manifestPath;
    private readonly string _keyPath;
    private readonly IReadOnlyList<string>? _targets;
    private readonly object _gate = new();
    private byte[]? _key;
    private volatile bool _manifestTampered;
    private bool _disposed;

    public RansomwareCanary(string root, IEnumerable<string>? targets = null)
    {
        _manifestPath = Path.Combine(root, "canaries.json");
        _keyPath = Path.Combine(root, "canary.key");
        _targets = targets?.ToList();
    }

    public string ManifestPath => _manifestPath;

    /// <summary>
    /// El manifiesto no coincide con su HMAC local. No implica que un atacante
    /// haya eludido la protección: solo que la baseline fue editada, corrupta
    /// o sustituida por una versión anterior.
    /// </summary>
    public bool ManifestTampered => _manifestTampered;

    public string IntegrityStatus { get; private set; } = "new";

    /// <summary>Número de operaciones de ACL que no pudieron aplicarse.</summary>
    public int AclFailures { get; private set; }

    public IReadOnlyList<string> Paths
    {
        get { lock (_gate) return _hashes.Keys.ToList(); }
    }

    public void Initialize()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_manifestPath)!);
        lock (_gate)
        {
            LoadKey();
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
                        RestrictOrCount(name);
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

    /// <summary>
    /// Sustituye la clave por una nueva y vuelve a firmar la baseline actual
    /// sin perder los hashes observados. Útil tras una sospecha de compromiso
    /// de la clave local o al cambiar la cuenta de ejecución del servicio.
    /// </summary>
    public void RotateKey()
    {
        lock (_gate)
        {
            ReplaceKey(RandomNumberGenerator.GetBytes(32));
            _manifestTampered = false;
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

    private void RestrictOrCount(string path)
    {
        if (OperatingSystem.IsWindows() && !LocalFileAcl.Restrict(path))
        {
            AclFailures++;
            IntegrityStatus = "acl-failed";
        }
    }

    private void LoadKey()
    {
        if (_key is not null) return;
        var keyExisted = File.Exists(_keyPath);
        if (keyExisted)
        {
            try
            {
                var blob = File.ReadAllBytes(_keyPath);
                var plain = OperatingSystem.IsWindows()
                    ? ProtectedData.Unprotect(blob, Entropy(), DataProtectionScope.CurrentUser)
                    : blob;
                if (plain.Length == 32)
                {
                    _key = plain;
                    return;
                }
                CryptographicOperations.ZeroMemory(plain);
            }
            catch (Exception ex) when (ex is CryptographicException or IOException or UnauthorizedAccessException)
            {
                // Clave corrupta o contexto DPAPI distinto: se genera una nueva
                // y el manifiesto antiguo se conserva como evidencia.
            }
        }
        // Una clave nueva en una instalación limpia no es manipulación; solo
        // lo es si existía una clave que no pudimos recuperar.
        if (keyExisted)
        {
            _manifestTampered = true;
            IntegrityStatus = "invalid";
        }
        ReplaceKey(RandomNumberGenerator.GetBytes(32));
    }

    private void ReplaceKey(byte[] key)
    {
        if (_key is not null) CryptographicOperations.ZeroMemory(_key);
        _key = key;
        WriteAtomic(_keyPath, OperatingSystem.IsWindows()
            ? ProtectedData.Protect(key, Entropy(), DataProtectionScope.CurrentUser)
            : key);
        RestrictOrCount(_keyPath);
    }

    private static byte[] Entropy() => Encoding.UTF8.GetBytes(KeyLabel + ".v" + KeyVersion.ToString(System.Globalization.CultureInfo.InvariantCulture));

    private void LoadManifest()
    {
        if (!File.Exists(_manifestPath)) return;
        try
        {
            var raw = File.ReadAllText(_manifestPath);
            var manifest = JsonSerializer.Deserialize<CanaryManifest>(raw, JsonDefaults.Options);
            if (manifest is null) throw new JsonException("Manifiesto vacío");

            IntegrityStatus = Verify(manifest) ? "ok" : "invalid";
            if (IntegrityStatus == "invalid")
            {
                _manifestTampered = true;
                // Conservar la baseline original: sobrescribirla destruiría la
                // evidencia de que fue editada.
                var preserved = Path.Combine(Path.GetDirectoryName(_manifestPath)!,
                    $"canaries.invalid-{Guid.NewGuid():N}.json");
                File.Copy(_manifestPath, preserved, false);
                _hashes.Clear();
                _alerted.Clear();
                return;
            }

            foreach (var (path, hash) in manifest.Hashes) _hashes[path] = hash;
            foreach (var (path, hash) in manifest.Alerted) _alerted[path] = hash;
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException or FormatException)
        {
            _hashes.Clear();
            _alerted.Clear();
            IntegrityStatus = "invalid";
            _manifestTampered = true;
        }
    }

    private bool Verify(CanaryManifest manifest)
    {
        // Un manifiesto sin versión ni firma es el formato heredado: se migra
        // una sola vez. Cualquier otra combinación con versión distinta de la
        // actual se rechaza, incluido un downgrade firmado.
        if (manifest.Version is null && string.IsNullOrEmpty(manifest.Signature)) return true;
        if (manifest.Version != ManifestVersion || string.IsNullOrWhiteSpace(manifest.Signature)) return false;
        try
        {
            var expected = Convert.FromHexString(Sign(manifest));
            var actual = Convert.FromHexString(manifest.Signature);
            return CryptographicOperations.FixedTimeEquals(expected, actual);
        }
        catch (FormatException) { return false; }
    }

    private string Sign(CanaryManifest manifest)
    {
        var canonical = new
        {
            version = ManifestVersion,
            keyVersion = KeyVersion,
            hashes = manifest.Hashes.OrderBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(x => x.Key, x => x.Value, StringComparer.OrdinalIgnoreCase),
            alerted = manifest.Alerted.OrderBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(x => x.Key, x => x.Value, StringComparer.OrdinalIgnoreCase)
        };
        return Convert.ToHexString(HMACSHA256.HashData(_key!,
            Encoding.UTF8.GetBytes(JsonSerializer.Serialize(canonical, JsonDefaults.Options)))).ToLowerInvariant();
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
        WriteAtomic(_manifestPath, Encoding.UTF8.GetBytes(JsonSerializer.Serialize(manifest, JsonDefaults.Options)));
        RestrictOrCount(_manifestPath);
        if (!_manifestTampered && IntegrityStatus != "acl-failed") IntegrityStatus = "ok";
    }

    private static void WriteAtomic(string path, byte[] content)
    {
        var temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                stream.Write(content);
                stream.Flush(true);
            }
            if (OperatingSystem.IsWindows() && !LocalFileAcl.Restrict(temp))
                throw new IOException("No se pudieron restringir los permisos del archivo temporal.");
            File.Move(temp, path, true);
        }
        finally
        {
            try { File.Delete(temp); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* mejor esfuerzo */ }
        }
    }

    private static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_key is not null)
        {
            CryptographicOperations.ZeroMemory(_key);
            _key = null;
        }
    }

    private sealed class CanaryManifest
    {
        // Sin inicializador: ausencia = manifiesto heredado no firmado.
        public int? Version { get; set; }
        public string Signature { get; set; } = string.Empty;
        public Dictionary<string, string> Hashes { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> Alerted { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }
}
