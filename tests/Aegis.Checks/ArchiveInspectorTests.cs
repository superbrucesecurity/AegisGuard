using System.IO.Compression;
using System.Text;
using Aegis.Core;

namespace Aegis.Tests;

public sealed class ArchiveInspectorTests
{
    private readonly ArchiveInspector _inspector = new();

    [Fact]
    public async Task EicarInsideZipIsVerifiedCritical()
    {
        var zip = CreateZip(("readme.txt", "inocuo"u8.ToArray()), ("muestra.txt", FileInspector.EicarSampleBytes));

        var matches = await _inspector.AnalyzeAsync(zip, ".zip");
        var eicar = Assert.Single(matches, m => m.RuleId == "EICAR-STANDARD-TEST");

        Assert.Equal(Severity.Critical, eicar.Severity);
        Assert.Equal("archive", eicar.Category);
        Assert.Contains(eicar.Evidence, e => e.Contains("muestra.txt", StringComparison.Ordinal));

        var observation = new Observation { Kind = EventKind.FileCreated, Subject = @"C:\Users\test\sample.zip" };
        var engine = new DecisionEngine();
        var local = engine.Assess(observation, matches, new HashSet<string>(StringComparer.OrdinalIgnoreCase));
        var decision = engine.Decide(observation, local, new PolicySettings
        {
            LearningMode = false,
            MonitorThreshold = 25,
            BlockThreshold = 58,
            QuarantineThreshold = 80,
            AutoQuarantine = true
        });
        Assert.True(local.HasVerifiedIndicator);
        Assert.Equal(Verdict.Quarantine, decision.Verdict);
    }

    [Fact]
    public async Task ExecutableMemberIsMediumNotCritical()
    {
        var zip = CreateZip(("herramienta.exe", "MZ contenido inocuo"u8.ToArray()));

        var matches = await _inspector.AnalyzeAsync(zip, ".zip");
        var member = Assert.Single(matches, m => m.RuleId == "ARCHIVE-EXECUTABLE-MEMBER");

        Assert.Equal(Severity.Medium, member.Severity);
        Assert.DoesNotContain(matches, m => m.Severity == Severity.Critical);
    }

    [Fact]
    public async Task NestedZipWithEicarIsDetected()
    {
        var inner = CreateZip(("muestra.txt", FileInspector.EicarSampleBytes));
        var outer = CreateZip(("inner.zip", inner));

        var matches = await _inspector.AnalyzeAsync(outer, ".zip");

        Assert.Contains(matches, m => m.RuleId == "ARCHIVE-NESTED");
        Assert.Contains(matches, m => m.RuleId == "EICAR-STANDARD-TEST");
    }

    [Fact]
    public async Task GzipWithEicarIsDetected()
    {
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.Fastest, leaveOpen: true))
            await gzip.WriteAsync(FileInspector.EicarSampleBytes);

        var matches = await _inspector.AnalyzeAsync(output.ToArray(), ".gz");
        Assert.Contains(matches, m => m.RuleId == "EICAR-STANDARD-TEST");
    }

    [Fact]
    public async Task OversizedTarMemberIsRejectedBeforeReading()
    {
        var header = new byte[512];
        "bomb.bin"u8.CopyTo(header.AsSpan(0, 8));
        "00200000001\0"u8.CopyTo(header.AsSpan(124, 12)); // 32 MiB + 1 en octal
        "ustar"u8.CopyTo(header.AsSpan(257, 5));
        header[156] = (byte)'0';

        var matches = await _inspector.AnalyzeAsync(header, ".tar");
        var bomb = Assert.Single(matches, m => m.RuleId == "ARCHIVE-BOMB");

        Assert.Equal(Severity.High, bomb.Severity);
        Assert.Contains(bomb.Evidence, e => e.Contains("bomb.bin", StringComparison.Ordinal));
    }

    private static byte[] CreateZip(params (string Name, byte[] Content)[] entries)
    {
        using var output = new MemoryStream();
        using (var zip = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var entry in entries)
            {
                var item = zip.CreateEntry(entry.Name, CompressionLevel.Fastest);
                using var stream = item.Open();
                stream.Write(entry.Content);
            }
        }
        return output.ToArray();
    }
}
