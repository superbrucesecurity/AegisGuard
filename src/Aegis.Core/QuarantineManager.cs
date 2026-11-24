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
    private byte[]? _key;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public QuarantineManager(string programDataRoot)
    {
        _root = Path.Combine(programDataRoot, "quarantine");
        _keyFile = Path.Combine(_root, "key.bin");
        _manifestFile = Path.Combine(_root, "manifest.json");
    }

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(_root);
        if (!File.Exists(_keyFile))
        {
            var key = RandomNumberGenerator.GetBytes(32);
            var protectedKey = ProtectedData.Protect(key, Entropy, DataProtectionScope.LocalMachine);
            await File.WriteAllBytesAsync(_keyFile, protectedKey).ConfigureAwait(false);
            CryptographicOperations.ZeroMemory(key);
        }
        var protectedBytes = await File.ReadAllBytesAsync(_keyFile).ConfigureAwait(false);
        _key = ProtectedData.Unprotect(protectedBytes, Entropy, DataProtectionScope.LocalMachine);
        if (!File.Exists(_manifestFile)) await WriteManifestAsync([]).ConfigureAwait(false);
    }

    public async Task<QuarantineItem> QuarantineAsync(string path, string reason, string threatId, string sha256, CancellationToken ct = default)
    {
        if (!PathPolicy.IsQuarantineSafe(path))
            throw new InvalidOperationException("La ruta está protegida y no puede ponerse en cuarentena.");
        if (!File.Exists(path)) throw new FileNotFoundException("El fichero ya no existe", path);

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            EnsureKey();
            var info = new FileInfo(path);
            var plain = await File.ReadAllBytesAsync(path, ct).ConfigureAwait(false);
            var item = new QuarantineItem
            {
                OriginalPath = Path.GetFullPath(path),
                Reason = reason,
                ThreatId = threatId,
                Sha256 = sha256,
                Length = plain.Length
            };

            var nonce = RandomNumberGenerator.GetBytes(NonceSize);
            var cipher = new byte[plain.Length];
            var tag = new byte[TagSize];
            using (var aes = new AesGcm(_key!, TagSize))
            {
                aes.Encrypt(nonce, plain, cipher, tag);
            }
            CryptographicOperations.ZeroMemory(plain);

            var payload = new byte[NonceSize + TagSize + cipher.Length];
            nonce.CopyTo(payload, 0);
            tag.CopyTo(payload, NonceSize);
            cipher.CopyTo(payload, NonceSize + TagSize);

            var payloadPath = Path.Combine(_root, item.Id + ".qtn");
            await File.WriteAllBytesAsync(payloadPath, payload, ct).ConfigureAwait(false);
            item.PayloadFile = Path.GetFileName(payloadPath);

            var items = await ReadManifestAsync().ConfigureAwait(false);
            items.Add(item);
            await WriteManifestAsync(items).ConfigureAwait(false);

            File.SetAttributes(path, FileAttributes.Normal);
            File.Delete(path);
            info.Refresh();
            return item;
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

            var payloadPath = Path.Combine(_root, item.PayloadFile);
            if (!File.Exists(payloadPath)) return false;
            var payload = await File.ReadAllBytesAsync(payloadPath, ct).ConfigureAwait(false);
            if (payload.Length < NonceSize + TagSize) return false;

            var plain = new byte[payload.Length - NonceSize - TagSize];
            using (var aes = new AesGcm(_key!, TagSize))
            {
                aes.Decrypt(payload.AsSpan(0, NonceSize), payload.AsSpan(NonceSize + TagSize), payload.AsSpan(NonceSize, TagSize), plain);
            }

            var directory = Path.GetDirectoryName(item.OriginalPath);
            if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);
            if (File.Exists(item.OriginalPath)) throw new IOException("El fichero original ya existe; no se sobrescribirá.");
            await File.WriteAllBytesAsync(item.OriginalPath, plain, ct).ConfigureAwait(false);

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
            if (item is null) return false;
            var payloadPath = Path.Combine(_root, item.PayloadFile);
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

    private async Task<List<QuarantineItem>> ReadManifestAsync()
    {
        if (!File.Exists(_manifestFile)) return [];
        var text = await File.ReadAllTextAsync(_manifestFile).ConfigureAwait(false);
        return JsonSerializer.Deserialize<List<QuarantineItem>>(text, JsonDefaults.Options) ?? [];
    }

    private async Task WriteManifestAsync(List<QuarantineItem> items)
    {
        var temp = _manifestFile + ".tmp";
        await File.WriteAllTextAsync(temp, JsonSerializer.Serialize(items, JsonDefaults.Options)).ConfigureAwait(false);
        File.Move(temp, _manifestFile, true);
    }
}
