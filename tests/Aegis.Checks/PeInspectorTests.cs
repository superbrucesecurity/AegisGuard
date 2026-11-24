using System.Buffers.Binary;
using Aegis.Core;

namespace Aegis.Tests;

public sealed class PeInspectorTests
{
    private static readonly PeInspector Inspector = new();

    [Fact]
    public void NonPeBytesProduceNoFindings()
    {
        Assert.Empty(Inspector.Analyze("esto no es un PE"u8));
    }

    [Fact]
    public void TruncatedHeaderIsNotTreatedAsMalware()
    {
        var matches = Inspector.Analyze("MZ"u8);

        var match = Assert.Single(matches);
        Assert.Equal("PE-MALFORMED-HEADER", match.RuleId);
        Assert.Equal(Severity.Low, match.Severity);
        Assert.Equal("pe", match.Category);
        Assert.DoesNotContain(matches, m => m.Severity == Severity.Critical);
    }

    [Fact]
    public void WritableExecutableSectionIsReported()
    {
        var image = BuildPe(sectionCharacteristics: 0xE0000020);

        var matches = Inspector.Analyze(image, image.Length);
        var match = Assert.Single(matches, m => m.RuleId == "PE-WRITABLE-EXECUTABLE-SECTION");

        Assert.Equal(Severity.Medium, match.Severity);
        Assert.Contains(match.Evidence, e => e.Contains(".text", StringComparison.Ordinal));
        Assert.DoesNotContain(matches, m => m.Severity == Severity.Critical);
    }

    [Fact]
    public void EntryPointOutsideExecutableSectionIsReported()
    {
        var image = BuildPe(sectionCharacteristics: 0x40000040); // CNT_INITIALIZED_DATA | MEM_READ

        var matches = Inspector.Analyze(image, image.Length);
        Assert.Contains(matches, m => m.RuleId == "PE-ENTRY-NONEXEC");
        Assert.DoesNotContain(matches, m => m.RuleId == "PE-WRITABLE-EXECUTABLE-SECTION");
    }

    [Fact]
    public void MissingHardeningNoImportsAndLargeOverlayAreReported()
    {
        var image = BuildPe(sectionCharacteristics: 0x60000020, overlayBytes: 1024 * 1024 + 1);

        var matches = Inspector.Analyze(image, image.Length + 1024 * 1024 + 1);
        Assert.Contains(matches, m => m.RuleId == "PE-MISSING-HARDENING");
        Assert.Contains(matches, m => m.RuleId == "PE-NO-IMPORTS");
        Assert.Contains(matches, m => m.RuleId == "PE-LARGE-OVERLAY");
    }

    private static byte[] BuildPe(uint sectionCharacteristics, int overlayBytes = 0)
    {
        const int peOffset = 0x80;
        const int optionalOffset = peOffset + 24;
        const int sectionOffset = optionalOffset + 224;
        var image = new byte[sectionOffset + 40 + 512 + overlayBytes];

        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(0, 2), 0x5A4D);
        BinaryPrimitives.WriteInt32LittleEndian(image.AsSpan(0x3C, 4), peOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(peOffset, 4), 0x00004550);
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(peOffset + 4, 2), 0x014C);
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(peOffset + 6, 2), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(peOffset + 20, 2), 224);
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(peOffset + 22, 2), 0x0102);

        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(optionalOffset, 2), 0x010B);
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(optionalOffset + 16, 4), 0x1000);

        ".text"u8.CopyTo(image.AsSpan(sectionOffset, 5));
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(sectionOffset + 8, 4), 0x200);
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(sectionOffset + 12, 4), 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(sectionOffset + 16, 4), 0x200);
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(sectionOffset + 20, 4), 0x200);
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(sectionOffset + 36, 4), sectionCharacteristics);
        return image;
    }
}
