using System.IO.Compression;
using Aegis.Core;

namespace Aegis.Tests;

public sealed class MacroInspectorTests
{
    private readonly MacroInspector _inspector = new();

    [Fact]
    public async Task OoxmlVbaProjectWithAutoRunAndExecutionIsHigh()
    {
        var vba = "Sub Auto_Open()\nCreateObject(\"WScript.Shell\").Shell(\"calc.exe\")\nEnd Sub"u8.ToArray();
        var document = CreateZip(("word/document.xml", "texto visible"u8.ToArray()), ("word/vbaProject.bin", vba));

        var matches = await _inspector.AnalyzeAsync(document, ".docx");

        Assert.Contains(matches, m => m.RuleId == "MACRO-PROJECT-PRESENT");
        var execution = Assert.Single(matches, m => m.RuleId == "MACRO-AUTORUN-EXECUTION");
        Assert.Equal(Severity.High, execution.Severity);
        Assert.Equal("macro", execution.Category);
        Assert.DoesNotContain(matches, m => m.Severity == Severity.Critical);
    }

    [Fact]
    public async Task VisibleTextIsNotTreatedAsMacroEvidence()
    {
        var document = CreateZip(("word/document.xml", "Auto_Open Shell( CreateObject"u8.ToArray()));

        var matches = await _inspector.AnalyzeAsync(document, ".docx");

        Assert.Empty(matches);
    }

    [Fact]
    public async Task UnreadableLegacyContainerIsUnverifiedNotMalicious()
    {
        var bytes = new byte[512];
        new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }.CopyTo(bytes, 0);

        var matches = await _inspector.AnalyzeAsync(bytes, ".doc");

        var unverified = Assert.Single(matches);
        Assert.Equal("MACRO-UNVERIFIED", unverified.RuleId);
        Assert.Equal(Severity.Info, unverified.Severity);
    }

    [Fact]
    public async Task UnsupportedExtensionProducesNoFindings()
    {
        Assert.Empty(await _inspector.AnalyzeAsync("x"u8.ToArray(), ".txt"));
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
