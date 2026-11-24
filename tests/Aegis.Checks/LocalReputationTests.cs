using Aegis.Core;

namespace Aegis.Tests;

public sealed class LocalReputationTests
{
    [Fact]
    public void UnknownKeyIsNeutral()
    {
        var reputation = new LocalReputation();
        Assert.Equal(0.5, reputation.Get("Nunca-visto"));
        Assert.Equal(0.5, reputation.Get(null));
    }

    [Fact]
    public void BenignHistoryRaisesReputation()
    {
        var reputation = new LocalReputation();
        for (var i = 0; i < 3; i++) reputation.Record("sha-benigno", malicious: false);

        Assert.True(reputation.Get("sha-benigno") > 0.5);
        Assert.True(reputation.Get("sha-benigno") <= 0.9);
    }

    [Fact]
    public void MaliciousHistoryNeedsCorroboration()
    {
        var reputation = new LocalReputation();
        reputation.Record("sha-malicioso", malicious: true);

        // Una sola decisión adversaria no crea un bucle de realimentación.
        Assert.Equal(0.35, reputation.Get("sha-malicioso"));
        Assert.Equal(0.5, reputation.Get("otro-sha"));

        reputation.Record("sha-malicioso", malicious: true);
        Assert.Equal(0.1, reputation.Get("sha-malicioso"));
    }

    [Fact]
    public void EntriesAreBounded()
    {
        var reputation = new LocalReputation();
        for (var i = 0; i < 5000; i++) reputation.Record($"hash-{i}", malicious: false);

        Assert.True(reputation.Count <= 4096);
    }

    [Fact]
    public async Task ReputationSurvivesRestart()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"aegis-reputation-{Guid.NewGuid():N}");
        var path = Path.Combine(directory, "reputation.json");
        try
        {
            var first = new LocalReputation(path);
            first.Record("sha-persistente", malicious: true);
            first.Record("sha-persistente", malicious: true);
            await first.SaveAsync();

            var second = new LocalReputation(path);
            Assert.Equal(0.1, second.Get("sha-persistente"));
            Assert.Equal(1, second.Count);
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [Fact]
    public void CorruptedStoreIsIgnored()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"aegis-reputation-{Guid.NewGuid():N}");
        var path = Path.Combine(directory, "reputation.json");
        try
        {
            Directory.CreateDirectory(directory);
            File.WriteAllText(path, "{\"entries\":[{\"key\":\"sha\",\"score\":0.1}],\"checksum\":\"malo\"}");
            var reputation = new LocalReputation(path);
            Assert.Equal(0.5, reputation.Get("sha"));
            Assert.Equal(0, reputation.Count);
        }
        finally { Directory.Delete(directory, recursive: true); }
    }
}
