using System.Text;
using Aegis.Core;

namespace Aegis.Tests;

public sealed class ScriptInspectorTests
{
    private readonly ScriptInspector _inspector = new();

    [Fact]
    public void EncodedPowerShellWithSeveralSignalsIsHigh()
    {
        var payload = Convert.ToBase64String(Encoding.UTF8.GetBytes("Invoke-Expression 'Write-Host ok'"));
        var script = Encoding.UTF8.GetBytes(
            $"[Convert]::FromBase64String('{payload}'); iex($decoded); New-Object -ComObject WScript.Shell");

        var matches = _inspector.Analyze(script, ".ps1");
        var match = Assert.Single(matches, m => m.RuleId == "SCRIPT-MULTIPLE-EXECUTION-SIGNALS");

        Assert.Equal(Severity.High, match.Severity);
        Assert.Equal("script", match.Category);
        Assert.DoesNotContain(matches, m => m.Severity == Severity.Critical);
    }

    [Fact]
    public void SingleSuspiciousTokenDoesNotBlock()
    {
        var matches = _inspector.Analyze("var x = WScript.CreateObject('WScript.Shell');"u8.ToArray(), ".js");

        var match = Assert.Single(matches);
        Assert.Equal("SCRIPT-SINGLE-SIGNAL", match.RuleId);
        Assert.Equal(Severity.Info, match.Severity);

        var observation = new Observation { Kind = EventKind.ManualScan, Subject = @"C:\Users\test\x.js" };
        var engine = new DecisionEngine();
        var local = engine.Assess(observation, matches, new HashSet<string>(StringComparer.OrdinalIgnoreCase));
        Assert.True(local.Score < 25);
    }

    [Fact]
    public void Utf16ScriptIsDecoded()
    {
        var script = Encoding.Unicode.GetBytes("powershell -enc AAAAAAAA; (New-Object Net.WebClient).DownloadString($u)");

        var matches = _inspector.Analyze(script, ".ps1");

        Assert.Contains(matches, m => m.RuleId == "SCRIPT-SUSPICIOUS-COMBINATION");
        Assert.DoesNotContain(matches, m => m.Severity == Severity.Critical);
    }

    [Fact]
    public void Base64EncodedEicarIsCritical()
    {
        var encoded = Convert.ToBase64String(FileInspector.EicarSampleBytes);
        var script = Encoding.UTF8.GetBytes($"[Convert]::FromBase64String('{encoded}')");

        var matches = _inspector.Analyze(script, ".ps1");
        var eicar = Assert.Single(matches, m => m.RuleId == "EICAR-STANDARD-TEST");

        Assert.Equal(Severity.Critical, eicar.Severity);
    }

    [Fact]
    public void UnsupportedExtensionProducesNoFindings()
    {
        Assert.Empty(_inspector.Analyze("Invoke-Expression"u8.ToArray(), ".txt"));
    }
}
