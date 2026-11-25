using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Aegis.Core;

namespace Aegis.Tests;

public sealed class IntelPackageTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "aegis-package-" + Guid.NewGuid().ToString("N"));
    private readonly string _package;

    public IntelPackageTests()
    {
        _package = Path.Combine(_root, "package");
        Directory.CreateDirectory(_package);
    }

    [Fact]
    public void ValidPackageIsAcceptedAndLoadsIntel()
    {
        var key = CreateKey();
        WritePackage(key, "1.2.3", "abc123");

        Assert.True(IntelPackage.TryVerify(_package, out var package, out var error), error);
        Assert.Equal("1.2.3", package!.Version);
        Assert.Equal(2, package.Files.Count);
        Assert.True(File.Exists(Path.Combine(_package, IntelPackage.IntelFileName)));

        var intel = new ThreatIntel();
        intel.Load(Path.Combine(_package, IntelPackage.IntelFileName));
        Assert.Equal(1, intel.HashCount);
        Assert.True(intel.IsMaliciousHash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"));
    }

    [Theory]
    [InlineData("tampered-rules")]
    [InlineData("tampered-signature")]
    [InlineData("tampered-key")]
    [InlineData("missing-file")]
    public void AnyTamperingIsRejected(string scenario)
    {
        var key = CreateKey();
        WritePackage(key, "1.0.0", "abc123");

        switch (scenario)
        {
            case "tampered-rules":
                File.AppendAllText(Path.Combine(_package, "threat-intel.json"), " ");
                break;
            case "tampered-signature":
                var sigPath = Path.Combine(_package, IntelPackage.SignatureFileName);
                var sig = Convert.FromBase64String(File.ReadAllText(sigPath).Trim());
                sig[10] ^= 0xFF;
                File.WriteAllText(sigPath, Convert.ToBase64String(sig));
                break;
            case "tampered-key":
                var keyPath = Path.Combine(_package, IntelPackage.PublicKeyFileName);
                var doc = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText(keyPath));
                var bad = new
                {
                    algorithm = "ECDSA-P256",
                    x = doc.GetProperty("x").GetString(),
                    y = doc.GetProperty("y").GetString(),
                    sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
                };
                File.WriteAllText(keyPath, JsonSerializer.Serialize(bad));
                break;
            case "missing-file":
                File.Delete(Path.Combine(_package, "eicar.yar"));
                break;
        }

        Assert.False(IntelPackage.TryVerify(_package, out var package, out var error), scenario);
        Assert.Null(package);
        Assert.False(string.IsNullOrWhiteSpace(error));
    }

    [Fact]
    public void ConfiguredKeyPinIsEnforcedByThePackageVerifier()
    {
        var key = CreateKey();
        WritePackage(key, "1.2.3", "abc123");
        var pin = KeyHash(key);

        Assert.True(IntelPackage.TryVerify(_package, pin, out _, out var okError), okError);
        Assert.False(IntelPackage.TryVerify(_package, new string('0', 64), out var rejected, out var error));
        Assert.Null(rejected);
        Assert.Contains("clave", error, StringComparison.Ordinal);
        Assert.False(IntelPackage.TryVerify(_package, "xyz", out _, out error));
        Assert.Contains("huella", error, StringComparison.Ordinal);
    }

    [Fact]
    public void HelperScriptSignsAndVerifiesRoundTrip()
    {
        if (!OperatingSystem.IsWindows()) return;
        var script = FindRepositoryFile(Path.Combine("deploy", "Build-IntelPackage.ps1"));
        if (script is null) return; // ejecución sin el árbol del repositorio: se valida en el smoke del servicio
        var keyPath = Path.Combine(_root, "dev-key.json");
        using var signingKey = CreateKey();
        var privateParameters = signingKey.ExportParameters(true);
        File.WriteAllText(keyPath, JsonSerializer.Serialize(new
        {
            algorithm = "ECDSA-P256",
            d = Convert.ToHexString(privateParameters.D!).ToLowerInvariant(),
            x = Convert.ToHexString(privateParameters.Q.X!).ToLowerInvariant(),
            y = Convert.ToHexString(privateParameters.Q.Y!).ToLowerInvariant()
        }));
        var output = Path.Combine(_root, "script-package");
        var psi = new ProcessStartInfo("powershell.exe")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        psi.ArgumentList.Add("-NoProfile");
        psi.ArgumentList.Add("-ExecutionPolicy");
        psi.ArgumentList.Add("Bypass");
        psi.ArgumentList.Add("-File");
        psi.ArgumentList.Add(script);
        psi.ArgumentList.Add("-SigningKeyPath");
        psi.ArgumentList.Add(keyPath);
        psi.ArgumentList.Add("-OutputPath");
        psi.ArgumentList.Add(output);
        using var process = Process.Start(psi)!;
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();
        Assert.True(process.ExitCode == 0, stdout + stderr);
        Assert.True(IntelPackage.TryVerify(output, out _, out var error), error);
    }

    private static string? FindRepositoryFile(string relative)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, relative);
            if (File.Exists(candidate)) return candidate;
            directory = directory.Parent;
        }
        return null;
    }

    private static ECDsa CreateKey() => ECDsa.Create(ECCurve.NamedCurves.nistP256);

    private static string KeyHash(ECDsa key)
    {
        var parameters = key.ExportParameters(false);
        return Convert.ToHexString(SHA256.HashData([.. parameters.Q.X!, .. parameters.Q.Y!])).ToLowerInvariant();
    }

    private void WritePackage(ECDsa key, string version, string id)
    {
        var intel = Path.Combine(_package, IntelPackage.IntelFileName);
        var yara = Path.Combine(_package, "eicar.yar");
        File.WriteAllText(intel, JsonSerializer.Serialize(new
        {
            maliciousSha256 = new[] { "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F" },
            maliciousDomains = Array.Empty<string>(),
            maliciousIps = Array.Empty<string>()
        }));
        File.WriteAllText(yara, $"rule sample_{id} {{ strings: $a = \"x\" condition: $a }}");
        var files = new[]
        {
            new IntelPackage.ManifestEntry { Path = "threat-intel.json", Name = "sha256:" + IntelPackage.ComputeSha256(intel) },
            new IntelPackage.ManifestEntry { Path = "eicar.yar", Name = "sha256:" + IntelPackage.ComputeSha256(yara) }
        };
        var manifestBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
        {
            version,
            createdUtc = DateTimeOffset.UtcNow.ToString("o"),
            files
        }, JsonDefaults.Options));
        File.WriteAllBytes(Path.Combine(_package, IntelPackage.ManifestFileName), manifestBytes);
        File.WriteAllText(Path.Combine(_package, IntelPackage.SignatureFileName),
            Convert.ToBase64String(key.SignData(manifestBytes, HashAlgorithmName.SHA256)));
        var parameters = key.ExportParameters(false);
        var x = Convert.ToHexString(parameters.Q.X!).ToLowerInvariant();
        var y = Convert.ToHexString(parameters.Q.Y!).ToLowerInvariant();
        var keyHash = KeyHash(key);
        File.WriteAllText(Path.Combine(_package, IntelPackage.PublicKeyFileName), JsonSerializer.Serialize(new
        {
            algorithm = "ECDSA-P256",
            x,
            y,
            sha256 = keyHash
        }));
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); }
        catch (IOException) { /* ignorar bloqueo temporal */ }
    }
}
