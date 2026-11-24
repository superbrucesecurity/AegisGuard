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
}
