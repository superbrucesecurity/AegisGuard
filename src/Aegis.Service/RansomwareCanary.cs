using System.Security.Cryptography;
using System.Text;

namespace Aegis.Service;

/// <summary>
/// Archivos señuelo ocultos en directorios de usuario. Un cambio en su
/// contenido es un indicador fuerte de cifrado masivo/ransomware.
/// </summary>
public sealed class RansomwareCanary
{
    private readonly Dictionary<string, string> _hashes = new(StringComparer.OrdinalIgnoreCase);
    private readonly string _manifestPath;

    public RansomwareCanary(string root)
    {
        _manifestPath = Path.Combine(root, "canaries.json");
    }

    public IReadOnlyList<string> Paths => _hashes.Keys.ToList();

    public void Initialize()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_manifestPath)!);
        var targets = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads")
        }.Where(p => !string.IsNullOrWhiteSpace(p) && Directory.Exists(p)).Distinct(StringComparer.OrdinalIgnoreCase);

        foreach (var target in targets)
        {
            var name = Path.Combine(target, $".aegis-canary-{Environment.MachineName.ToLowerInvariant()}.txt");
            if (!File.Exists(name))
            {
                var content = $"AEGIS Guard canary. Do not modify. {Guid.NewGuid():N}{Environment.NewLine}";
                File.WriteAllText(name, content, Encoding.UTF8);
                File.SetAttributes(name, FileAttributes.Hidden | FileAttributes.System | FileAttributes.ReadOnly);
            }
            _hashes[name] = Hash(File.ReadAllBytes(name));
        }
    }

    public bool IsCanary(string path) => _hashes.ContainsKey(path);

    public bool WasModified(string path)
    {
        if (!_hashes.TryGetValue(path, out var expected) || !File.Exists(path)) return false;
        try
        {
            return !string.Equals(expected, Hash(File.ReadAllBytes(path)), StringComparison.OrdinalIgnoreCase);
        }
        catch (IOException) { return true; }
        catch (UnauthorizedAccessException) { return true; }
    }

    public void Refresh(string path)
    {
        if (_hashes.ContainsKey(path) && File.Exists(path)) _hashes[path] = Hash(File.ReadAllBytes(path));
    }

    private static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
}
