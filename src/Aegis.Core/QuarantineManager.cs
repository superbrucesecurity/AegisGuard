using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;

namespace Aegis.Core;

[SupportedOSPlatform("windows")]
public sealed class QuarantineManager
{
    private static readonly byte[] Entropy = "AegisGuard.Quarantine.v1"u8.ToArray();
    private const int NonceSize = 12;
    private const int TagSize = 16;

    private readonly string _root;
    private readonly string _keyFile;
    private readonly string _manifestFile;
    private readonly string _applicationDataDir;
    private byte[]? _key;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public QuarantineManager(string programDataRoot)
    {
        _root = Path.Combine(programDataRoot, "quarantine");
        _keyFile = Path.Combine(_root, "key.bin");
        _manifestFile = Path.Combine(_root, "manifest.json");
        _applicationDataDir = Path.GetFullPath(programDataRoot);
    }

    public async Task InitializeAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            Directory.CreateDirectory(_root);
            if (!File.Exists(_keyFile))
            {
                var key = RandomNumberGenerator.GetBytes(32);
                var protectedKey = ProtectedData.Protect(key, Entropy, DataProtectionScope.LocalMachine);
                try
                {
                    // CreateNew evita que dos inicializaciones concurrentes
                    // sobrescriban la clave y dejen la cuarentena irrecuperable.
                    using var stream = new FileStream(_keyFile, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                    await stream.WriteAsync(protectedKey).ConfigureAwait(false);
                }
                catch (IOException)
                {
                    // Otra instancia ganó la carrera; se lee su clave más abajo.
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(key);
                }
            }
            var protectedBytes = await File.ReadAllBytesAsync(_keyFile).ConfigureAwait(false);
            _key = ProtectedData.Unprotect(protectedBytes, Entropy, DataProtectionScope.LocalMachine);
            if (!File.Exists(_manifestFile)) await WriteManifestAsync([]).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<QuarantineItem> QuarantineAsync(string path, string reason, string threatId, string sha256, CancellationToken ct = default)
    {
        if (!PathPolicy.IsQuarantineSafe(path, _applicationDataDir))
            throw new InvalidOperationException("La ruta está protegida y no puede ponerse en cuarentena.");
        if (!File.Exists(path)) throw new FileNotFoundException("El fichero ya no existe", path);

        // Comprobar el tamaño antes de asignar el buffer: ReadAllBytesAsync de
        // un fichero gigante provocaría OOM antes de poder rechazarlo.
        var declaredLength = new FileInfo(path).Length;
        if (declaredLength > AnalysisLimits.MaxScanBytes)
            throw new IOException("El fichero supera el límite de cuarentena (512 MB).");

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            EnsureKey();
            var plain = await File.ReadAllBytesAsync(path, ct).ConfigureAwait(false);
            if (plain.Length > AnalysisLimits.MaxScanBytes)
                throw new IOException("El fichero supera el límite de cuarentena (512 MB).");
            var actualHash = Convert.ToHexString(SHA256.HashData(plain));
            if (!string.IsNullOrWhiteSpace(sha256) &&
                !string.Equals(actualHash, sha256, StringComparison.OrdinalIgnoreCase))
                throw new IOException("El fichero cambió desde el análisis; no se pone en cuarentena.");

            var item = new QuarantineItem
            {
                OriginalPath = Path.GetFullPath(path),
                Reason = reason,
                ThreatId = threatId,
                Sha256 = actualHash,
                Length = plain.Length
            };

            var nonce = RandomNumberGenerator.GetBytes(NonceSize);
            var cipher = new byte[plain.Length];
            var tag = new byte[TagSize];
            using (var aes = new AesGcm(_key!, TagSize))
                aes.Encrypt(nonce, plain, cipher, tag);
            CryptographicOperations.ZeroMemory(plain);

            var payload = new byte[NonceSize + TagSize + cipher.Length];
            nonce.CopyTo(payload, 0);
            tag.CopyTo(payload, NonceSize);
            cipher.CopyTo(payload, NonceSize + TagSize);

            var payloadPath = Path.Combine(_root, item.Id + ".qtn");
            await File.WriteAllBytesAsync(payloadPath, payload, ct).ConfigureAwait(false);
            item.PayloadFile = Path.GetFileName(payloadPath);

            File.SetAttributes(path, FileAttributes.Normal);
            try
            {
                File.Delete(path);
            }
            catch
            {
                File.Delete(payloadPath);
                throw;
            }

            // El manifiesto solo se escribe cuando el original ya fue retirado.
            var items = await ReadManifestAsync().ConfigureAwait(false);
            items.Add(item);
            await WriteManifestAsync(items).ConfigureAwait(false);
            return item;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<QuarantineItem?> GetAsync(string id, CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var items = await ReadManifestAsync().ConfigureAwait(false);
            return items.FirstOrDefault(x => x.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<bool> RestoreAsync(string id, CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            EnsureKey();
            var items = await ReadManifestAsync().ConfigureAwait(false);
            var item = items.FirstOrDefault(x => x.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
            if (item is null || item.Restored) return false;
            if (!TryResolvePayload(item.PayloadFile, out var payloadPath)) return false;
            // La ruta original del manifiesto es editable: se valida de nuevo.
            if (!PathPolicy.IsQuarantineSafe(item.OriginalPath, _applicationDataDir)) return false;
            if (!File.Exists(payloadPath)) return false;
            var payload = await File.ReadAllBytesAsync(payloadPath, ct).ConfigureAwait(false);
            if (payload.Length < NonceSize + TagSize) return false;

            var plain = new byte[payload.Length - NonceSize - TagSize];
            try
            {
                using var aes = new AesGcm(_key!, TagSize);
                aes.Decrypt(payload.AsSpan(0, NonceSize), payload.AsSpan(NonceSize + TagSize),
                    payload.AsSpan(NonceSize, TagSize), plain);
            }
            catch (CryptographicException)
            {
                CryptographicOperations.ZeroMemory(plain);
                return false; // payload manipulado o clave incorrecta
            }

            if (!string.Equals(item.Sha256, Convert.ToHexString(SHA256.HashData(plain)), StringComparison.OrdinalIgnoreCase))
            {
                CryptographicOperations.ZeroMemory(plain);
                return false;
            }

            var directory = Path.GetDirectoryName(item.OriginalPath);
            if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);
            if (File.Exists(item.OriginalPath))
            {
                CryptographicOperations.ZeroMemory(plain);
                throw new IOException("El fichero original ya existe; no se sobrescribirá.");
            }
            await File.WriteAllBytesAsync(item.OriginalPath, plain, ct).ConfigureAwait(false);
            CryptographicOperations.ZeroMemory(plain);

            item.Restored = true;
            await WriteManifestAsync(items).ConfigureAwait(false);
            return true;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<bool> PurgeAsync(string id, CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var items = await ReadManifestAsync().ConfigureAwait(false);
            var item = items.FirstOrDefault(x => x.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
            if (item is null || !TryResolvePayload(item.PayloadFile, out var payloadPath)) return false;
            if (File.Exists(payloadPath)) File.Delete(payloadPath);
            items.Remove(item);
            await WriteManifestAsync(items).ConfigureAwait(false);
            return true;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<List<QuarantineItem>> ListAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try { return await ReadManifestAsync().ConfigureAwait(false); }
        finally { _gate.Release(); }
    }

    private void EnsureKey()
    {
        if (_key is null) throw new InvalidOperationException("La cuarentena no está inicializada.");
    }

    private bool TryResolvePayload(string? payloadFile, out string path)
    {
        path = string.Empty;
        // Un manifest editado no puede escapar del directorio de cuarentena.
        if (string.IsNullOrWhiteSpace(payloadFile)) return false;
        if (!string.Equals(Path.GetFileName(payloadFile), payloadFile, StringComparison.Ordinal)) return false;
        if (!payloadFile.EndsWith(".qtn", StringComparison.OrdinalIgnoreCase)) return false;
        var root = Path.GetFullPath(_root).TrimEnd(Path.DirectorySeparatorChar);
        var full = Path.GetFullPath(Path.Combine(root, payloadFile));
        if (!full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) return false;
        path = full;
        return true;
    }

    private async Task<List<QuarantineItem>> ReadManifestAsync()
    {
        if (!File.Exists(_manifestFile)) return [];
        var text = await File.ReadAllTextAsync(_manifestFile).ConfigureAwait(false);
        return JsonSerializer.Deserialize<List<QuarantineItem>>(text, JsonDefaults.Options) ?? [];
    }

    private async Task WriteManifestAsync(List<QuarantineItem> items)
    {
        var temp = _manifestFile + "." + Guid.NewGuid().ToString("N") + ".tmp";
        await File.WriteAllTextAsync(temp, JsonSerializer.Serialize(items, JsonDefaults.Options)).ConfigureAwait(false);
        File.Move(temp, _manifestFile, true);
    }
}
