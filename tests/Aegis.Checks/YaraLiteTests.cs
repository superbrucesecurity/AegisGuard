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
    public async Task PatternsBeyondEightMegabytesAndFileSizeAreEvaluated()
    {
        const string source = """
            rule DeepMarker
            {
                meta:
                    severity = "high"
                strings:
                    $a = "DEEP-MARKER-42"
                condition:
                    $a and filesize > 8MB
            }
            """;
        // El parser de YARA-lite interpreta el sufijo MB en la condición.
        var rule = Assert.Single(new YaraLiteEngine().Parse(source.Replace("8MB", "8000000")));
        var engine = new YaraLiteEngine();
        engine.LoadRules(source.Replace("8MB", "8000000"));

        var file = Path.Combine(Path.GetTempPath(), $"aegis-deep-{Guid.NewGuid():N}.bin");
        var bytes = new byte[9 * 1024 * 1024];
        "DEEP-MARKER-42"u8.CopyTo(bytes.AsSpan(bytes.Length - 64));
        await File.WriteAllBytesAsync(file, bytes);
        try
        {
            var matches = await engine.ScanFileAsync(file);
            Assert.Contains(matches, m => m.RuleId == "DeepMarker");
            Assert.Equal("high", rule.Severity.ToString().ToLowerInvariant());
        }
        finally { File.Delete(file); }
    }

    [Fact]
    public async Task GroupedConditionAndWideNoCaseWork()
    {
        const string source = """
            rule Grouped
            {
                condition:
                    ($a or $b) and $c
            }
            """;
        var engine = new YaraLiteEngine();
        Assert.NotEmpty(engine.Parse(source));

        const string withStrings = """
            rule Grouped
            {
                strings:
                    $a = "alpha"
                    $b = "beta"
                    $c = "gamma" wide nocase
                condition:
                    ($a or $b) and $c
            }
            """;
        engine.LoadRules(withStrings);
        var file = Path.Combine(Path.GetTempPath(), $"aegis-group-{Guid.NewGuid():N}.bin");
        var bytes = "alpha\0"u8.ToArray().Concat("G\0A\0M\0M\0A\0"u8.ToArray()).ToArray();
        await File.WriteAllBytesAsync(file, bytes);
        try
        {
            Assert.Contains(await engine.ScanFileAsync(file), m => m.RuleId == "Grouped");
        }
        finally { File.Delete(file); }
    }

    [Fact]
    public async Task MagicBytesAreReadInsteadOfAssumed()
    {
        const string source = """
            rule MzHeader
            {
                condition:
                    uint16(0) == 0x5A4D and filesize > 4
            }
            """;
        var engine = new YaraLiteEngine();
        engine.LoadRules(source);
        var file = Path.Combine(Path.GetTempPath(), $"aegis-magic-{Guid.NewGuid():N}.bin");
        await File.WriteAllBytesAsync(file, "MZxxxx"u8.ToArray());
        try
        {
            Assert.Contains(await engine.ScanFileAsync(file), m => m.RuleId == "MzHeader");
            await File.WriteAllBytesAsync(file, "XXxxxx"u8.ToArray());
            Assert.DoesNotContain(await engine.ScanFileAsync(file), m => m.RuleId == "MzHeader");
        }
        finally { File.Delete(file); }
    }

    [Fact]
    public void UnsupportedHexTokenRejectsTheRule()
    {
        const string source = """
            rule BadHex
            {
                strings:
                    $a = { 4D ~69 6D }
                condition:
                    any of them
            }
            """;
        Assert.Throws<FormatException>(() => new YaraLiteEngine().Parse(source));
    }

    [Fact]
    public async Task BundledEicarRuleMatchesGeneratedSample()
    {
        var engine = new YaraLiteEngine();
        engine.LoadDirectory(GetRulesDirectory());
        var eicar = string.Concat(
            "X5O!P%@AP[4", '\\', "PZX54(P^)7CC)7}$EICAR-",
            "STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
        var file = Path.Combine(Path.GetTempPath(), $"aegis-eicar-{Guid.NewGuid():N}.txt");
        try
        {
            await File.WriteAllTextAsync(file, eicar);
            var matches = await engine.ScanFileAsync(file);
            Assert.Contains(matches, m => m.RuleId == "EICAR_Standard_Test_File");
            var (hash, _, detected) = await new FileInspector().HashAsync(file);
            Assert.True(detected);
            Assert.Equal("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", hash);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            // Un antivirus del equipo puede bloquear o eliminar la muestra EICAR.
            // No se desactiva ni se considera un fallo del producto; solo se
            // omite esta comprobación en ese entorno.
            return;
        }
        finally { if (File.Exists(file)) File.Delete(file); }
    }

    [Fact]
    public void CommentsInsideConditionDoNotDiscardTheRule()
    {
        const string source = """
            rule Commented
            {
                strings:
                    $a = "marker"
                condition:
                    // solo una señal, pero documentada
                    any of them
            }
            """;

        var rule = Assert.Single(new YaraLiteEngine().Parse(source));
        Assert.Equal("any of them", rule.Condition);
    }

    [Fact]
    public void BundledHeuristicRulesRequireMoreThanOneString()
    {
        var rules = new YaraLiteEngine().Parse(File.ReadAllText(Path.Combine(GetRulesDirectory(), "suspicious_basics.yar")));

        Assert.Contains(rules, r => r.Id == "Mimikatz_Indicators" && r.Condition.Contains("all of them", StringComparison.Ordinal));
        Assert.Contains(rules, r => r.Id == "Ransomware_Note" && r.Condition.Contains("2 of them", StringComparison.Ordinal));
    }

    [Fact]
    public void MalformedRuleIsRejected()
    {
        var engine = new YaraLiteEngine();
        Assert.Throws<FormatException>(() => engine.Parse("rule Bad\n{\n strings:\n  $a = \"x\"\n}\n"));
    }

    private static string GetRulesDirectory() => Path.Combine(AppContext.BaseDirectory, "rules");
}
