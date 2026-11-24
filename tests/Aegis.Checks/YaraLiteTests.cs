using Aegis.Core;

namespace Aegis.Tests;

public sealed class YaraLiteTests
{
    [Fact]
    public void LoadsBundledRules()
    {
        var engine = new YaraLiteEngine();
        var loaded = engine.LoadDirectory(GetRulesDirectory());
        Assert.True(loaded >= 5);

        var eicarRule = engine.Parse(File.ReadAllText(Path.Combine(GetRulesDirectory(), "eicar.yar")));
        Assert.Contains(eicarRule, r => r.Id == "EICAR_Standard_Test_File" && r.Severity == Severity.Critical);
    }

    [Fact]
    public async Task BenignFileDoesNotMatch()
    {
        var engine = new YaraLiteEngine();
        engine.LoadDirectory(GetRulesDirectory());
        var file = Path.Combine(Path.GetTempPath(), $"aegis-benign-{Guid.NewGuid():N}.txt");
        await File.WriteAllTextAsync(file, "Este fichero contiene texto normal de prueba.");
        try
        {
            var matches = await engine.ScanFileAsync(file);
            Assert.Empty(matches);
        }
        finally { File.Delete(file); }
    }

    [Fact]
    public async Task HexPatternAndWideModifierWork()
    {
        const string source = """
            rule HexTest
            {
                meta:
                    severity = "high"
                    description = "secuencia hexadecimal"
                strings:
                    $a = { 41 42 ?? 44 }
                    $w = "abc" wide
                condition:
                    all of them
            }
            """;
        var engine = new YaraLiteEngine();
        var parsed = engine.Parse(source);
        Assert.Single(parsed);
        Assert.Equal(2, parsed[0].Patterns.Count);
        Assert.Equal("all of them", parsed[0].Condition.Trim());
        Assert.Equal(1, engine.LoadRules(source));

        var file = Path.Combine(Path.GetTempPath(), $"aegis-hex-{Guid.NewGuid():N}.bin");
        var bytes = "ABXD"u8.ToArray().Concat("a\0b\0c\0"u8.ToArray()).ToArray();
        Assert.True(parsed[0].Patterns[0].IsMatch(bytes), "patrón hexadecimal");
        Assert.True(parsed[0].Patterns[1].IsMatch(bytes), "patrón wide");
        await File.WriteAllBytesAsync(file, bytes);
        try
        {
            var matches = await engine.ScanFileAsync(file);
            Assert.Contains(matches, m => m.RuleId == "HexTest");
        }
        finally { File.Delete(file); }
    }

    [Fact]
    public void MalformedRuleIsRejected()
    {
        var engine = new YaraLiteEngine();
        Assert.Throws<FormatException>(() => engine.Parse("rule Bad\n{\n strings:\n  $a = \"x\"\n}\n"));
    }

    private static string GetRulesDirectory() => Path.Combine(AppContext.BaseDirectory, "rules");
}
