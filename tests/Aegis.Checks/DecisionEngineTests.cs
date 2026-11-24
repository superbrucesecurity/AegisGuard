using Aegis.Core;

namespace Aegis.Tests;

public sealed class DecisionEngineTests
{
    private readonly DecisionEngine _engine = new();
    private readonly PolicySettings _policy = new()
    {
        LearningMode = false,
        MonitorThreshold = 25,
        BlockThreshold = 58,
        QuarantineThreshold = 80,
        AiWeight = 0.3,
        AutoQuarantine = true
    };

    [Fact]
    public void CleanObservationWithoutAiIsAllowed()
    {
        var observation = new Observation
        {
            Kind = EventKind.ProcessStarted,
            Subject = @"C:\Program Files\App\app.exe",
            Signature = SignatureStatus.SignedTrusted
        };
        var local = _engine.Assess(observation, [], new HashSet<string>(StringComparer.OrdinalIgnoreCase));
        var decision = _engine.Decide(observation, local, new AiClassification(), _policy);

        Assert.Equal(Verdict.Allow, decision.Verdict);
        Assert.Equal(Severity.Info, decision.Severity);
        Assert.Equal(0, local.EvidenceCount);
    }

    [Fact]
    public void AiAloneNeverBlocksOrQuarantines()
    {
        var observation = new Observation { Kind = EventKind.ManualScan, Subject = @"C:\Temp\unknown.bin" };
        var local = _engine.Assess(observation, [], new HashSet<string>(StringComparer.OrdinalIgnoreCase));
        var ai = new AiClassification
        {
            IsValid = true,
            Model = "d1.2-ultra",
            ChoiceLabel = "MALICIOUS",
            Malicious = 0.97,
            Suspicious = 0.02,
            Clean = 0.01,
            Confidence = 0.95,
            SeverityScore = 3
        };

        var decision = _engine.Decide(observation, local, ai, _policy);

        Assert.Equal(Verdict.Monitor, decision.Verdict);
        Assert.True(decision.AiWasDecisive);
        Assert.DoesNotContain(decision.Verdict, new[] { Verdict.Block, Verdict.Quarantine });
    }

    [Fact]
    public void KnownMaliciousHashForcesQuarantineEvenWithoutAi()
    {
        const string hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
        var observation = new Observation { Kind = EventKind.FileCreated, Subject = @"C:\Users\test\eicar.txt", Sha256 = hash };
        var hashes = new HashSet<string>([hash], StringComparer.OrdinalIgnoreCase);
        var local = _engine.Assess(observation, [], hashes);
        var decision = _engine.Decide(observation, local, new AiClassification { Error = "sin conexión" }, _policy);

        Assert.True(local.HasCriticalIndicator);
        Assert.Equal(Verdict.Quarantine, decision.Verdict);
        Assert.Equal(Severity.Critical, decision.Severity);
        Assert.Equal(100, decision.Risk);
    }

    [Fact]
    public void CriticalRuleOnFileIsQuarantined()
    {
        var observation = new Observation { Kind = EventKind.ManualScan, Subject = @"C:\Users\test\sospechoso.exe" };
        var rules = new[] { new RuleMatch { RuleId = "Mimikatz_Indicators", Name = "Mimikatz", Severity = Severity.Critical } };
        var local = _engine.Assess(observation, rules, new HashSet<string>(StringComparer.OrdinalIgnoreCase));
        var decision = _engine.Decide(observation, local, new AiClassification(), _policy);

        Assert.Equal(Verdict.Quarantine, decision.Verdict);
        Assert.Contains(decision.Reasons, r => r.Contains("Mimikatz_Indicators", StringComparison.Ordinal));
    }

    [Fact]
    public void PolicyValidationKeepsThresholdsOrdered()
    {
        var policy = new PolicySettings { MonitorThreshold = 90, BlockThreshold = 10, QuarantineThreshold = 20, AiWeight = 4, MaxEvents = 99999 };
        policy.Validate();

        Assert.True(policy.MonitorThreshold < policy.BlockThreshold);
        Assert.True(policy.BlockThreshold < policy.QuarantineThreshold);
        Assert.True(policy.QuarantineThreshold <= 100);
        Assert.Equal(0.5, policy.AiWeight);
        Assert.Equal(5000, policy.MaxEvents);
    }

    [Fact]
    public void HighVolumeDecisionsStayFast()
    {
        var observation = new Observation { Kind = EventKind.DnsQuery, Subject = "example.invalid", BehaviorFlags = ["c2_beacon"] };
        var local = _engine.Assess(observation, [], new HashSet<string>(StringComparer.OrdinalIgnoreCase));
        var started = System.Diagnostics.Stopwatch.StartNew();
        for (var i = 0; i < 5000; i++) _engine.Decide(observation, local, new AiClassification(), _policy);
        started.Stop();

        Assert.True(started.Elapsed < TimeSpan.FromSeconds(5), $"5000 decisiones tardaron {started.ElapsedMilliseconds} ms");
    }
}
