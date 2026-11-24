using System.Text.Json.Nodes;
using Aegis.Service;

namespace Aegis.Tests;

public sealed class RansomwareCanaryTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "aegis-canary-" + Guid.NewGuid().ToString("N"));
    private readonly string _target;

    public RansomwareCanaryTests()
    {
        _target = Path.Combine(_root, "perfil");
        Directory.CreateDirectory(_target);
    }

    [Fact]
    public void EditedManifestIsDetected()
    {
        var canary = new RansomwareCanary(_root, [_target]);
        canary.Initialize();
        Assert.Equal("ok", canary.IntegrityStatus);
        Assert.False(canary.ManifestTampered);

        ChangeFirstHash();

        var reloaded = new RansomwareCanary(_root, [_target]);
        reloaded.Initialize();
        Assert.Equal("invalid", reloaded.IntegrityStatus);
        Assert.True(reloaded.ManifestTampered);
    }

    [Fact]
    public void UnsignedLegacyManifestIsMigratedOnce()
    {
        var canary = new RansomwareCanary(_root, [_target]);
        canary.Initialize();

        var document = JsonNode.Parse(File.ReadAllText(Path.Combine(_root, "canaries.json")))!.AsObject();
        document.Remove("version");
        document.Remove("signature");
        File.WriteAllText(Path.Combine(_root, "canaries.json"), document.ToJsonString());

        var migrated = new RansomwareCanary(_root, [_target]);
        migrated.Initialize();
        Assert.False(migrated.ManifestTampered);
        var signed = JsonNode.Parse(File.ReadAllText(Path.Combine(_root, "canaries.json")))!.AsObject();
        Assert.Equal(2, (int?)signed["version"]);
        Assert.False(string.IsNullOrWhiteSpace((string?)signed["signature"]));

        ChangeFirstHash();
        var tampered = new RansomwareCanary(_root, [_target]);
        tampered.Initialize();
        Assert.True(tampered.ManifestTampered);
    }

    private void ChangeFirstHash()
    {
        var path = Path.Combine(_root, "canaries.json");
        var document = JsonNode.Parse(File.ReadAllText(path))!.AsObject();
        var hashes = document["hashes"]!.AsObject();
        var first = hashes.First();
        hashes[first.Key] = new string('0', 64);
        File.WriteAllText(path, document.ToJsonString());
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_root))
            {
                foreach (var file in Directory.EnumerateFiles(_root, "*", SearchOption.AllDirectories))
                    File.SetAttributes(file, FileAttributes.Normal);
                Directory.Delete(_root, true);
            }
        }
        catch (IOException) { /* bloqueo temporal del sistema de archivos */ }
        catch (UnauthorizedAccessException) { /* atributos protegidos por otro proceso */ }
    }
}
