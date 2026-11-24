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
}
