using System.Reflection;
using Aegis.Core;

namespace Aegis.Tests;

public sealed class FileInspectorTests
{
    [Fact]
    public async Task ComputesStableHashAndLength()
    {
        if (!OperatingSystem.IsWindows()) return;
        var file = Path.Combine(Path.GetTempPath(), $"aegis-hash-{Guid.NewGuid():N}.txt");
        const string content = "Contenido inocuo para pruebas de hashing.";
        await File.WriteAllTextAsync(file, content);
        try
        {
            var inspector = new FileInspector();
            var (hash, length, eicar) = await inspector.HashAsync(file);

            Assert.Equal(System.Text.Encoding.UTF8.GetByteCount(content), length);
            Assert.Equal(64, hash.Length);
            Assert.All(hash, c => Assert.Contains(c, "0123456789abcdef"));
            Assert.False(eicar);
        }
        finally { File.Delete(file); }
    }

    [Fact]
    public async Task InspectKeepsHashOfFullFileAndBoundedPrefix()
    {
        if (!OperatingSystem.IsWindows()) return;
        var file = Path.Combine(Path.GetTempPath(), $"aegis-inspect-{Guid.NewGuid():N}.bin");
        var content = new byte[4096];
        Random.Shared.NextBytes(content);
        await File.WriteAllBytesAsync(file, content);
        try
        {
            var inspector = new FileInspector();
            var result = await inspector.InspectAsync(file, prefixBytes: 16);

            Assert.False(result.Truncated);
            Assert.Equal(4096, result.Length);
            Assert.Equal(16, result.Prefix.Length);
            Assert.Equal(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(content)).ToLowerInvariant(),
                result.Sha256);
        }
        finally { File.Delete(file); }
    }

    [Fact]
    public async Task InspectReportsTruncatedHashWithoutReadingWholeFile()
    {
        if (!OperatingSystem.IsWindows()) return;
        var file = Path.Combine(Path.GetTempPath(), $"aegis-inspect-{Guid.NewGuid():N}.bin");
        var content = new byte[4096];
        Random.Shared.NextBytes(content);
        await File.WriteAllBytesAsync(file, content);
        try
        {
            var inspector = new FileInspector();
            var result = await inspector.InspectAsync(file, maxBytes: 10, prefixBytes: 10);

            Assert.True(result.Truncated);
            Assert.Equal(4096, result.Length);
            Assert.Equal(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(content.AsSpan(0, 10)))
                .ToLowerInvariant(), result.Sha256);
        }
        finally { File.Delete(file); }
    }

    [Fact]
    public async Task ReadBytesHonoursArchiveCap()
    {
        if (!OperatingSystem.IsWindows()) return;
        var file = Path.Combine(Path.GetTempPath(), $"aegis-read-{Guid.NewGuid():N}.bin");
        await File.WriteAllBytesAsync(file, new byte[100]);
        try
        {
            var (bytes, truncated, length) = await new FileInspector().ReadBytesAsync(file, maxBytes: 10);
            Assert.Equal(10, bytes.Length);
            Assert.True(truncated);
            Assert.Equal(100, length);
        }
        finally { File.Delete(file); }
    }

    [Fact]
    public void EicarSampleBytesAreRecognizedInMemory()
    {
        // No se escribe la muestra en disco: otros antivirus pueden bloquearla
        // y el test debe verificar al motor, no permisos de terceros.
        Assert.Equal(68, FileInspector.EicarSampleBytes.Length);
        Assert.Equal("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(FileInspector.EicarSampleBytes)).ToLowerInvariant());
        Assert.True(FileInspector.ContainsEicarSample(FileInspector.EicarSampleBytes));
        Assert.False(FileInspector.ContainsEicarSample(System.Text.Encoding.ASCII.GetBytes("texto inocuo")));
        Assert.True(FileInspector.ContainsEicarSample(
            System.Text.Encoding.ASCII.GetBytes("INICIO" + System.Text.Encoding.ASCII.GetString(FileInspector.EicarSampleBytes) + "FIN")));
    }

    [Fact]
    public void EicarIsFoundAcrossReadBoundaries()
    {
        var sample = FileInspector.EicarSampleBytes;
        var scanner = new FileInspector.EicarScanner();
        scanner.Scan(System.Text.Encoding.ASCII.GetBytes("prefijo"));
        scanner.Scan(sample.AsSpan(0, 31));
        Assert.False(scanner.Found);
        scanner.Scan(sample.AsSpan(31));
        Assert.True(scanner.Found);
    }

    [Fact]
    public void WinTrustStateActionsUseDocumentedValues()
    {
        var type = typeof(FileInspector);
        var verify = type.GetField("WtdStateActionVerify", BindingFlags.NonPublic | BindingFlags.Static);
        var close = type.GetField("WtdStateActionClose", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(verify);
        Assert.NotNull(close);
        Assert.Equal(1u, Convert.ToUInt32(verify!.GetRawConstantValue()));
        Assert.Equal(2u, Convert.ToUInt32(close!.GetRawConstantValue()));
    }

    [Theory]
    [InlineData(0, SignatureStatus.SignedTrusted)]
    [InlineData(unchecked((int)0x800B0100), SignatureStatus.Unsigned)]  // TRUST_E_NOSIGNATURE
    [InlineData(unchecked((int)0x800B0003), SignatureStatus.Unsigned)]  // TRUST_E_SUBJECT_FORM_UNKNOWN
    [InlineData(unchecked((int)0x800B0001), SignatureStatus.Unsigned)]  // TRUST_E_PROVIDER_UNKNOWN
    [InlineData(unchecked((int)0x800B0109), SignatureStatus.SignedUntrusted)] // CERT_E_UNTRUSTEDROOT
    [InlineData(unchecked((int)0x800B010C), SignatureStatus.SignedUntrusted)] // CERT_E_REVOKED
    [InlineData(unchecked((int)0x80096010), SignatureStatus.SignedUntrusted)] // TRUST_E_BAD_DIGEST
    [InlineData(unchecked((int)0x800B010E), SignatureStatus.ChainNotVerifiable)] // CERT_E_REVOCATION_FAILURE
    [InlineData(unchecked((int)0x80092012), SignatureStatus.ChainNotVerifiable)] // CRYPT_E_REVOCATION_OFFLINE
    [InlineData(unchecked((int)0x80092010), SignatureStatus.Unknown)] // CRYPT_E_FILE_ERROR
    [InlineData(unchecked((int)0x80070005), SignatureStatus.Unknown)] // ERROR_ACCESS_DENIED
    [InlineData(unchecked((int)0x80070057), SignatureStatus.Unknown)] // E_INVALIDARG
    public void WinTrustStatusesAreClassifiedLocally(int status, SignatureStatus expected) =>
        Assert.Equal(expected, FileInspector.ClassifyWinTrustStatus(status));
}
