using Aegis.Core;
using Aegis.Service;
using Microsoft.Extensions.Logging.Abstractions;

namespace Aegis.Tests;

public sealed class DetectionPipelineTests
{
    [Fact]
    public async Task ManualScanUsesStructuralAnalyzerAndPersistsReputation()
    {
        if (!OperatingSystem.IsWindows()) return;
        var root = Path.Combine(Path.GetTempPath(), $"aegis-pipeline-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var file = Path.Combine(root, ".payload.ps1");
        var script = "[Convert]::FromBase64String('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'); iex($x); WScript.Shell";
        await File.WriteAllTextAsync(file, script);
        var reputationPath = Path.Combine(root, "reputation.json");

        try
        {
            var state = new RuntimeState();
            state.UpdatePolicy(new PolicySettings
            {
                LearningMode = false,
                AutoQuarantine = false,
                AutoBlockNetwork = false,
                MonitorThreshold = 25,
                BlockThreshold = 58,
                QuarantineThreshold = 80,
                MaxEvents = 100
            });
            var reputation = new LocalReputation(reputationPath);
            var store = new EventStore(root, 100);
            await store.InitializeAsync();
            var quarantine = new QuarantineManager(root);
            await quarantine.InitializeAsync();
            var canary = new RansomwareCanary(root);
            canary.Initialize();

            var pipeline = new DetectionPipeline(
                new YaraLiteEngine(),
                new ThreatIntel(),
                quarantine,
                store,
                state,
                reputation,
                new FirewallManager(),
                canary,
                NullLogger<DetectionPipeline>.Instance);

            var threat = await pipeline.ScanPathAsync(file);

            Assert.Equal(64, threat.Observation.Sha256!.Length);
            Assert.True(threat.Observation.FileSize > 0);
            Assert.Contains(threat.Observation.RuleMatches, m => m.Category == "script");
            Assert.Contains(threat.Decision.Local.Contributions, c => c.Source == "script");
            Assert.Contains(threat.Decision.Reasons, r => r.StartsWith("script:", StringComparison.Ordinal));
            Assert.NotEqual(Verdict.Allow, threat.Decision.Verdict);
            Assert.True(File.Exists(reputationPath));
            // La política de prueba desactiva la cuarentena: el veredicto se
            // registra sin mover el fichero del usuario.
            Assert.True(File.Exists(file));
        }
        finally
        {
            // Un resultado Block sin cuarentena no elimina el fichero; si una
            // política distinta lo movió, la limpieza sigue siendo segura.
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ReadOnlyScanUsesTheRealEngineWithoutPersistingOrRemediating()
    {
        if (!OperatingSystem.IsWindows()) return;
        var root = Path.Combine(Path.GetTempPath(), $"aegis-readonly-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var file = Path.Combine(root, ".payload.ps1");
        var script = "[Convert]::FromBase64String('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'); iex($x); WScript.Shell";
        await File.WriteAllTextAsync(file, script);

        try
        {
            var state = new RuntimeState();
            state.UpdatePolicy(new PolicySettings
            {
                LearningMode = false,
                AutoQuarantine = true,
                AutoBlockNetwork = true,
                MonitorThreshold = 25,
                BlockThreshold = 58,
                QuarantineThreshold = 80,
                MaxEvents = 100
            });
            var reputation = new LocalReputation(Path.Combine(root, "reputation.json"));
            var store = new EventStore(root, 100);
            await store.InitializeAsync();
            var quarantine = new QuarantineManager(root);
            await quarantine.InitializeAsync();
            var canary = new RansomwareCanary(root);
            canary.Initialize();
            var correlation = new CorrelationEngine();

            var pipeline = new DetectionPipeline(
                new YaraLiteEngine(),
                new ThreatIntel(),
                quarantine,
                store,
                state,
                reputation,
                new FirewallManager(),
                canary,
                NullLogger<DetectionPipeline>.Instance,
                correlation);

            var threat = await pipeline.ScanPathReadOnlyAsync(file);

            // Motor real: la decisión no es un valor inventado ni "Allow" por omisión.
            Assert.Equal(64, threat.Observation.Sha256!.Length);
            Assert.Contains(threat.Observation.RuleMatches, m => m.Category == "script");
            Assert.NotEqual(Verdict.Allow, threat.Decision.Verdict);

            // El informe es una proyección del análisis real y tampoco persiste.
            Assert.NotNull(threat.Report);
            Assert.Equal("1.0", threat.Report.SchemaVersion);
            Assert.Contains(threat.Report.Analyzers,
                a => a.Category == "script" && a.Ran && a.Findings.Any(f => f.Category == "script"));
            Assert.Equal(threat.Decision.Local.Contributions.Count, threat.Report.Contributions.Count);
            Assert.Equal(threat.Decision.Local.Score, threat.Report.Summary.Score);
            Assert.True(threat.Report.Coverage.HashReconfirmed);

            // Ningún efecto secundario, aunque la política permita remediar.
            Assert.False(File.Exists(Path.Combine(root, "events.jsonl")));
            Assert.False(File.Exists(Path.Combine(root, "threats.jsonl")));
            Assert.False(File.Exists(Path.Combine(root, "reputation.json")));
            Assert.True(File.Exists(file));
            Assert.Empty(await quarantine.ListAsync());
            var status = state.Snapshot(firewallActive: true);
            Assert.Equal(0, status.EventsTotal);
            Assert.Equal(0, status.ThreatsTotal);
            Assert.Equal(0, status.BlockedTotal);
            Assert.Equal(0, status.QuarantinedTotal);
            Assert.Equal(0, correlation.BufferedEvents);
            Assert.Equal(0, correlation.KeyCount);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}
