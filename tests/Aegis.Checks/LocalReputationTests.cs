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
    public void MaliciousHistoryLowersReputation()
    {
        var reputation = new LocalReputation();
        reputation.Record("sha-malicioso", malicious: true);

        Assert.Equal(0.1, reputation.Get("sha-malicioso"));
        Assert.Equal(0.5, reputation.Get("otro-sha"));
    }

    [Fact]
    public void EntriesAreBounded()
    {
        var reputation = new LocalReputation();
        for (var i = 0; i < 5000; i++) reputation.Record($"hash-{i}", malicious: false);

        Assert.True(reputation.Count <= 4096);
    }
}
