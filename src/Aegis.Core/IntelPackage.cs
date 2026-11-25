using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Aegis.Core;

/// <summary>
/// Paquete local de inteligencia: manifiesto con hashes SHA-256 de los ficheros
/// incluidos y firma ECDSA P-256 de ese manifiesto. No descarga nada y no usa
/// claves remotas; la clave pública incluye su propio SHA-256 para detectar
/// sustituciones de la clave. La cadena de confianza se fija en el ejecutable
/// mediante AEGIS_INTEL_KEY_SHA256; si no se define, no se carga ningún paquete.
/// </summary>
public sealed class IntelPackage
{
    public const string ManifestFileName = "manifest.json";
    public const string SignatureFileName = "manifest.sig";
    public const string PublicKeyFileName = "public-key.json";
    public const string IntelFileName = "threat-intel.json";

    private const int MaxManifestBytes = 1_048_576;
    private const int MaxFileBytes = 16 * 1024 * 1024;
    private const int MaxFiles = 512;

    public string Version { get; set; } = string.Empty;
    public DateTimeOffset CreatedUtc { get; set; }
    public List<ManifestEntry> Files { get; set; } = [];

    /// <summary>
    /// Valida firma, clave, ficheros y, si se indica, la huella fijada de la
    /// clave. Sin pin se comprueba únicamente la integridad interna del paquete.
    /// </summary>
    public static bool TryVerify(string directory, out IntelPackage? package, out string error) =>
        TryVerify(directory, null, out package, out error);

    /// <summary>
    /// Valida la firma del manifiesto, la clave pública, todos los ficheros
    /// incluidos y la huella de clave configurada por el administrador. Devuelve
    /// false sin lanzar excepción ante cualquier alteración. Los ficheros no
    /// listados se ignoran: no amplían la inteligencia activa.
    /// </summary>
    public static bool TryVerify(string directory, string? expectedKeyHash,
        out IntelPackage? package, out string error)
    {
        package = null;
        error = string.Empty;
        if (!string.IsNullOrWhiteSpace(expectedKeyHash) &&
            (expectedKeyHash.Length != 64 || expectedKeyHash.Any(c => !Uri.IsHexDigit(c))))
        {
            error = "huella de clave configurada no válida";
            return false;
        }
        try
        {
            var manifestPath = Path.Combine(directory, ManifestFileName);
            var signaturePath = Path.Combine(directory, SignatureFileName);
            var keyPath = Path.Combine(directory, PublicKeyFileName);
            if (!File.Exists(manifestPath) || !File.Exists(signaturePath) || !File.Exists(keyPath))
            {
                error = "faltan manifiesto, firma o clave pública";
                return false;
            }
            if (new FileInfo(manifestPath).Length > MaxManifestBytes ||
                new FileInfo(signaturePath).Length > MaxManifestBytes ||
                new FileInfo(keyPath).Length > MaxManifestBytes)
            {
                error = "tamaño de metadatos fuera de límite";
                return false;
            }

            var manifestBytes = File.ReadAllBytes(manifestPath);
            var signature = Convert.FromBase64String(File.ReadAllText(signaturePath).Trim());
            var keyDocument = JsonSerializer.Deserialize<PublicKeyDocument>(
                File.ReadAllText(keyPath), JsonDefaults.Options);
            if (keyDocument?.Algorithm != "ECDSA-P256" || string.IsNullOrWhiteSpace(keyDocument.X) ||
                string.IsNullOrWhiteSpace(keyDocument.Y))
            {
                error = "clave pública no válida";
                return false;
            }
            var keyHash = Convert.ToHexString(
                SHA256.HashData([.. keyDocument.Xu8, .. keyDocument.Yu8])).ToLowerInvariant();
            if (!string.Equals(keyHash, keyDocument.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                error = "checksum de clave pública no coincide";
                return false;
            }
            if (!string.IsNullOrWhiteSpace(expectedKeyHash) &&
                !string.Equals(keyHash, expectedKeyHash, StringComparison.OrdinalIgnoreCase))
            {
                error = "clave pública no fijada por el administrador";
                return false;
            }

            var parameters = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = Convert.FromHexString(keyDocument.X),
                    Y = Convert.FromHexString(keyDocument.Y)
                }
            };
            using var ecdsa = ECDsa.Create(parameters);
            if (!ecdsa.VerifyData(manifestBytes, signature, HashAlgorithmName.SHA256))
            {
                error = "firma del manifiesto no válida";
                return false;
            }

            var parsed = JsonSerializer.Deserialize<IntelPackage>(manifestBytes, JsonDefaults.Options);
            if (parsed is null || string.IsNullOrWhiteSpace(parsed.Version) || parsed.Files.Count == 0 ||
                parsed.Files.Count > MaxFiles)
            {
                error = "manifiesto incompleto";
                return false;
            }
            foreach (var entry in parsed.Files)
            {
                var name = Path.GetFileName(entry.Path);
                var expectedHash = NormalizeEntryHash(entry.Name);
                if (string.IsNullOrWhiteSpace(name) || name != entry.Path ||
                    name is ManifestFileName or SignatureFileName or PublicKeyFileName || expectedHash is null)
                {
                    error = $"entrada de manifiesto no válida: {entry.Path}";
                    return false;
                }
                var target = Path.Combine(directory, name);
                if (!File.Exists(target) || new FileInfo(target).Length > MaxFileBytes ||
                    !string.Equals(ComputeSha256(target), expectedHash, StringComparison.OrdinalIgnoreCase))
                {
                    error = $"hash no coincide: {name}";
                    return false;
                }
            }
            package = parsed;
            return true;
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException or
                                   FormatException or CryptographicException or ArgumentException)
        {
            error = "paquete ilegible o mal formado";
            return false;
        }
    }

    public static string ComputeSha256(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    private static string? NormalizeEntryHash(string value)
    {
        var hash = value.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase)
            ? value["sha256:".Length..]
            : value;
        if (hash.Length != 64 || hash.Any(c => !Uri.IsHexDigit(c))) return null;
        return hash.ToLowerInvariant();
    }

    public sealed class ManifestEntry
    {
        [JsonPropertyName("path")] public string Path { get; set; } = string.Empty;
        [JsonPropertyName("sha256")] public string Name { get; set; } = string.Empty;
    }

    private sealed class PublicKeyDocument
    {
        [JsonPropertyName("algorithm")] public string? Algorithm { get; set; }
        [JsonPropertyName("x")] public string? X { get; set; }
        [JsonPropertyName("y")] public string? Y { get; set; }
        [JsonPropertyName("sha256")] public string? Sha256 { get; set; }

        [JsonIgnore]
        public byte[] Xu8 => Convert.FromHexString(X ?? string.Empty);
        [JsonIgnore]
        public byte[] Yu8 => Convert.FromHexString(Y ?? string.Empty);
    }
}
