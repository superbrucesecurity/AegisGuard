using Aegis.Core;

namespace Aegis.Tests;

public sealed class CorrelationEngineTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 25, 10, 0, 0, TimeSpan.Zero);
    private static readonly PolicySettings Policy = new()
    {
        LearningMode = false,
        MonitorThreshold = 10,
        BlockThreshold = 20,
        QuarantineThreshold = 80,
        AutoQuarantine = true
    };

    [Fact]
    public void SuspiciousProcessThenPublicNetworkIsCorrelated()
    {
        var now = T0;
        var engine = new CorrelationEngine(clock: () => now);
        var anchor = Anchor("anchor", "42", T0);
        var network = Network("net", "42", T0.AddSeconds(12));

        Assert.Empty(engine.Observe(anchor));
        var matches = engine.Observe(network);

        var match = Assert.Single(matches);
        Assert.Equal(CorrelationEngine.ProcessNetworkRule, match.RuleId);
        Assert.Equal(12, match.Weight);
        Assert.Equal(2, match.Evidence.Count);
        Assert.Contains(match.Evidence, e => e.ObservationId == "anchor" && e.Kind == EventKind.ProcessStarted);
        Assert.Contains(match.Evidence, e => e.ObservationId == "net" && e.Details.Contains("remote=8.8.8.8"));

        network.RemoteAddress = "10.0.0.1"; // evita la señal de red independiente
        var local = new DecisionEngine().Assess(network, [], Hashes(), matches);
        Assert.Equal(12, local.Score);
        Assert.Single(local.Correlations);
        Assert.False(local.HasCriticalIndicator);
        Assert.False(local.HasVerifiedIndicator);
    }

    [Fact]
    public void NetworkAloneDoesNotCorrelate()
    {
        var engine = new CorrelationEngine(clock: () => T0);

        Assert.Empty(engine.Observe(Network("net", "42", T0)));
        Assert.Equal(1, engine.BufferedEvents);
    }

    [Fact]
    public void DifferentPidsAndExpiredWindowDoNotCorrelate()
    {
        var engine = new CorrelationEngine(clock: () => T0);
        engine.Observe(Anchor("anchor", "42", T0));

        Assert.Empty(engine.Observe(Network("other-pid", "99", T0.AddSeconds(2))));
        Assert.Empty(engine.Observe(Network("late", "42", T0.AddSeconds(121))));
    }

    [Fact]
    public void OutOfOrderEventsAreCorrelatedByTimestamp()
    {
        var engine = new CorrelationEngine(clock: () => T0);
        // La cola crítico-primero puede entregar la red antes que el proceso.
        Assert.Empty(engine.Observe(Network("net", "42", T0.AddSeconds(8))));

        var matches = engine.Observe(Anchor("anchor", "42", T0));

        Assert.Equal(CorrelationEngine.ProcessNetworkRule, Assert.Single(matches).RuleId);
    }

    [Fact]
    public void PersistenceRequiresAnObservedPid()
    {
        var engine = new CorrelationEngine(clock: () => T0);
        engine.Observe(Anchor("anchor", "42", T0));

        var withoutPid = new Observation
        {
            Id = "no-pid",
            Timestamp = T0.AddSeconds(10),
            Kind = EventKind.PersistenceChanged,
            Subject = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Payload",
            BehaviorFlags = ["persistence_registry"]
        };
        Assert.Empty(engine.Observe(withoutPid));

        var withPid = new Observation
        {
            Id = "persist",
            Timestamp = T0.AddSeconds(12),
            Kind = EventKind.PersistenceChanged,
            Subject = withoutPid.Subject,
            ProcessId = "42",
            BehaviorFlags = ["persistence_registry"]
        };
        var match = Assert.Single(engine.Observe(withPid));
        Assert.Equal(CorrelationEngine.ProcessPersistenceRule, match.RuleId);
    }

    [Fact]
    public void TriggerMatchesOnlyTheMostRecentAnchor()
    {
        var engine = new CorrelationEngine(clock: () => T0);
        engine.Observe(Anchor("old", "42", T0));
        engine.Observe(Anchor("new", "42", T0.AddSeconds(10)));

        var matches = engine.Observe(Network("net", "42", T0.AddSeconds(12)));

        var match = Assert.Single(matches);
        Assert.Contains(match.Evidence, e => e.ObservationId == "new");
        Assert.DoesNotContain(match.Evidence, e => e.ObservationId == "old");
    }

    [Fact]
    public void SameRuleFiresOncePerAnchor()
    {
        var engine = new CorrelationEngine(clock: () => T0);
        engine.Observe(Anchor("anchor", "42", T0));

        var total = 0;
        for (var i = 1; i <= 10; i++)
            total += engine.Observe(Network($"net-{i}", "42", T0.AddSeconds(i))).Count;

        Assert.Equal(1, total);
    }

    [Fact]
    public void BuffersAndFiredKeysStayBounded()
    {
        var options = new CorrelationOptions();
        var engine = new CorrelationEngine(options, clock: () => T0);

        for (var i = 0; i < 1500; i++)
            engine.Observe(Anchor($"anchor-{i}", i.ToString(), T0));

        Assert.True(engine.KeyCount <= options.MaxKeys);
        Assert.True(engine.BufferedEvents <= options.MaxKeys * options.MaxEventsPerKey);
    }

    [Fact]
    public void TtlPrunesOldEvidence()
    {
        var now = T0;
        var engine = new CorrelationEngine(clock: () => now);
        engine.Observe(Anchor("anchor", "42", T0));
        engine.Observe(Network("net", "42", T0.AddSeconds(5)));
        Assert.Equal(1, engine.KeyCount);

        now = T0.AddMinutes(11);
        Assert.Equal(0, engine.KeyCount);
        Assert.Equal(0, engine.BufferedEvents);
    }

    [Fact]
    public void CorrelationAloneNeverBlocksOrQuarantines()
    {
        var engine = new CorrelationEngine(clock: () => T0);
        engine.Observe(Anchor("anchor", "42", T0));
        var matches = engine.Observe(Network("net", "42", T0.AddSeconds(3)));
        // La dirección pública ya se puntúa por separado; para comprobar la
        // salvaguarda se evalúa una observación sin esa señal adicional.
        var network = Network("net", "42", T0.AddSeconds(3));
        network.RemoteAddress = "10.0.0.1";

        var assessor = new DecisionEngine();
        var decision = assessor.Decide(network, assessor.Assess(network, [], Hashes(), matches), Policy);

        Assert.Equal(Verdict.Monitor, decision.Verdict);
        Assert.True(decision.Risk <= Policy.BlockThreshold - 1);
        Assert.True(decision.Confidence <= 0.60);
        Assert.False(decision.Local.HasVerifiedIndicator);
    }

    [Fact]
    public void ReasonsIncludeCorrelationEvidenceIds()
    {
        var engine = new CorrelationEngine(clock: () => T0);
        engine.Observe(Anchor("anchor-id", "42", T0));
        var network = Network("network-id", "42", T0.AddSeconds(4));
        var matches = engine.Observe(network);
        var rules = new[]
        {
            new RuleMatch
            {
                RuleId = "STRONG-RULE", Name = "Señal fuerte", Severity = Severity.High, Category = "yara"
            }
        };

        var local = new DecisionEngine().Assess(network, rules, Hashes(), matches);
        var decision = new DecisionEngine().Decide(network, local, Policy);

        Assert.Contains(decision.Reasons, r =>
            r.Contains(CorrelationEngine.ProcessNetworkRule, StringComparison.Ordinal) &&
            r.Contains("anchor-id", StringComparison.Ordinal) &&
            r.Contains("network-id", StringComparison.Ordinal));
    }

    [Fact]
    public void PublicIpClassifierExcludesPrivateAndDocumentationRanges()
    {
        Assert.True(TelemetryAddress.IsPublicIp("8.8.8.8"));
        Assert.True(TelemetryAddress.IsPublicIp("2606:4700:4700::1111"));
        Assert.False(TelemetryAddress.IsPublicIp("127.0.0.1"));
        Assert.False(TelemetryAddress.IsPublicIp("10.0.0.1"));
        Assert.False(TelemetryAddress.IsPublicIp("192.168.1.1"));
        Assert.False(TelemetryAddress.IsPublicIp("169.254.1.1"));
        Assert.False(TelemetryAddress.IsPublicIp("203.0.113.10"));
        Assert.False(TelemetryAddress.IsPublicIp("no-es-una-ip"));
    }

    private static Observation Anchor(string id, string pid, DateTimeOffset at) => new()
    {
        Id = id,
        Timestamp = at,
        Kind = EventKind.ProcessStarted,
        Subject = @"C:\Temp\payload.exe",
        ProcessId = pid,
        BehaviorFlags = ["temp_execution"],
        Source = "etw-process"
    };

    private static Observation Network(string id, string pid, DateTimeOffset at) => new()
    {
        Id = id,
        Timestamp = at,
        Kind = EventKind.NetworkConnection,
        Subject = "network",
        ProcessId = pid,
        RemoteAddress = "8.8.8.8",
        RemotePort = "443",
        Source = "etw-network"
    };

    private static HashSet<string> Hashes() => new(StringComparer.OrdinalIgnoreCase);
}
