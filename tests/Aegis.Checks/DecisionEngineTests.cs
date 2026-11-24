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
        AutoQuarantine = true
    };

    [Fact]
    public void CleanObservationIsAllowed()
    {
        var observation = new Observation
        {
            Kind = EventKind.ProcessStarted,
            Subject = @"C:\Program Files\App\app.exe",
            Signature = SignatureStatus.SignedTrusted
        };
        var local = _engine.Assess(observation, [], new HashSet<string>(StringComparer.OrdinalIgnoreCase));
        var decision = _engine.Decide(observation, local, _policy);

        Assert.Equal(Verdict.Allow, decision.Verdict);
        Assert.Equal(Severity.Info, decision.Severity);
        Assert.Equal(0, local.EvidenceCount);
    }

    [Fact]
    public void KnownMaliciousHashForcesQuarantine()
    {
        const string hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
        var observation = new Observation { Kind = EventKind.FileCreated, Subject = @"C:\Users\test\eicar.txt", Sha256 = hash };
        var hashes = new HashSet<string>([hash], StringComparer.OrdinalIgnoreCase);
        var local = _engine.Assess(observation, [], hashes);
        var decision = _engine.Decide(observation, local, _policy);

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
        var decision = _engine.Decide(observation, local, _policy);

        Assert.Equal(Verdict.Quarantine, decision.Verdict);
        Assert.Contains(decision.Reasons, r => r.Contains("Mimikatz_Indicators", StringComparison.Ordinal));
    }

    [Fact]
    public void MediumRulesOnlyRaiseMonitoring()
    {
        var observation = new Observation { Kind = EventKind.ManualScan, Subject = @"C:\Temp\sample.bin" };
        var rules = new[]
        {
            new RuleMatch { RuleId = "R1", Name = "R1", Severity = Severity.Medium },
            new RuleMatch { RuleId = "R2", Name = "R2", Severity = Severity.Medium }
        };
        var local = _engine.Assess(observation, rules, new HashSet<string>(StringComparer.OrdinalIgnoreCase));

        Assert.Equal(44, local.Score);
        Assert.Equal(Verdict.Monitor, _engine.Decide(observation, local, _policy).Verdict);
    }

    [Fact]
    public void CriticalHashBlocksWhenQuarantineDisabled()
    {
        const string hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
        var policy = new PolicySettings
        {
            LearningMode = false,
            AutoQuarantine = false,
            MonitorThreshold = 25,
            BlockThreshold = 58,
            QuarantineThreshold = 80
        };
        var observation = new Observation { Kind = EventKind.FileCreated, Subject = @"C:\Temp\eicar.txt", Sha256 = hash };
        var local = _engine.Assess(observation, [], new HashSet<string>([hash], StringComparer.OrdinalIgnoreCase));

        Assert.Equal(Verdict.Block, _engine.Decide(observation, local, policy).Verdict);
    }

    [Fact]
    public void UnknownBehaviorFlagsAreIgnored()
    {
        var observation = new Observation
        {
            Kind = EventKind.ProcessStarted,
            Subject = @"C:\Program Files\App\app.exe",
            Signature = SignatureStatus.SignedTrusted,
            BehaviorFlags = ["process_injection", "av_tampering", "rootkit"]
        };
        var local = _engine.Assess(observation, [], new HashSet<string>(StringComparer.OrdinalIgnoreCase));

        Assert.Equal(0, local.Score);
        Assert.False(local.HasCriticalIndicator);
        Assert.False(local.HasVerifiedIndicator);
        Assert.Equal(Verdict.Allow, _engine.Decide(observation, local, _policy).Verdict);
    }

    [Fact]
    public void CanaryManifestTamperingIsCriticalLocalEvidence()
    {
        var observation = new Observation
        {
            Kind = EventKind.PersistenceChanged,
            Subject = @"C:\ProgramData\AegisGuard\canaries.json",
            BehaviorFlags = ["canary_manifest_tampered"]
        };
        var local = _engine.Assess(observation, [], new HashSet<string>(StringComparer.OrdinalIgnoreCase));

        Assert.Equal(55, local.Score);
        Assert.True(local.HasCriticalIndicator);
        Assert.False(local.HasVerifiedIndicator);
    }

    [Fact]
    public void KnownHashSetsVerifiedIndicator()
    {
        const string hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
        var observation = new Observation { Kind = EventKind.ManualScan, Subject = @"C:\Temp\eicar.txt", Sha256 = hash };
        var local = _engine.Assess(observation, [], new HashSet<string>([hash], StringComparer.OrdinalIgnoreCase));

        Assert.True(local.HasVerifiedIndicator);
        Assert.True(local.HasCriticalIndicator);
    }

    [Fact]
    public void PolicyValidationKeepsThresholdsOrdered()
    {
        var policy = new PolicySettings { MonitorThreshold = 90, BlockThreshold = 10, QuarantineThreshold = 20, MaxEvents = 99999 };
        policy.Validate();

        Assert.True(policy.MonitorThreshold < policy.BlockThreshold);
        Assert.True(policy.BlockThreshold < policy.QuarantineThreshold);
        Assert.True(policy.QuarantineThreshold <= 100);
        Assert.Equal(5000, policy.MaxEvents);
    }

    [Fact]
    public void DuplicateRuleMatchesDoNotInflateTheScore()
    {
        var observation = new Observation { Kind = EventKind.ManualScan, Subject = @"C:\Temp\sample.exe" };
        var rules = new[]
        {
            new RuleMatch { RuleId = "Mimikatz_Indicators", Name = "Mimikatz", Severity = Severity.Critical },
            new RuleMatch { RuleId = "mimikatz_indicators", Name = "Mimikatz", Severity = Severity.Critical }
        };
        var local = _engine.Assess(observation, rules, new HashSet<string>(StringComparer.OrdinalIgnoreCase));

        Assert.Equal(65, local.Score);
    }

    [Fact]
    public void SaturatedThresholdsStayBelow100()
    {
        var policy = new PolicySettings { MonitorThreshold = 100, BlockThreshold = 100, QuarantineThreshold = 100 };
        policy.Validate();

        Assert.True(policy.MonitorThreshold < policy.BlockThreshold);
        Assert.True(policy.BlockThreshold < policy.QuarantineThreshold);
        Assert.Equal(100, policy.QuarantineThreshold);
    }

    [Theory]
    [InlineData("::1", false)]
    [InlineData("127.0.0.1", false)]
    [InlineData("100.64.0.1", false)]
    [InlineData("8.8.8.8", true)]
    public void PublicIpDetectionExcludesNonRoutableAddresses(string address, bool expected)
    {
        var observation = new Observation { Kind = EventKind.NetworkConnection, Subject = "app.exe", RemoteAddress = address };
        var local = _engine.Assess(observation, [], new HashSet<string>(StringComparer.OrdinalIgnoreCase));

        Assert.Equal(expected, local.Contributions.Any(c => c.Source == "network"));
    }

    [Fact]
    public void HighVolumeDecisionsStayFast()
    {
        var observation = new Observation { Kind = EventKind.DnsQuery, Subject = "example.invalid", BehaviorFlags = ["c2_beacon"] };
        var local = _engine.Assess(observation, [], new HashSet<string>(StringComparer.OrdinalIgnoreCase));
        var started = System.Diagnostics.Stopwatch.StartNew();
        for (var i = 0; i < 5000; i++) _engine.Decide(observation, local, _policy);
        started.Stop();

        Assert.True(started.Elapsed < TimeSpan.FromSeconds(5), $"5000 decisiones tardaron {started.ElapsedMilliseconds} ms");
    }
}
