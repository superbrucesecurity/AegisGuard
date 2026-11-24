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
}
