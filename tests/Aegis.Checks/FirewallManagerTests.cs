using Aegis.Core;

namespace Aegis.Tests;

public sealed class FirewallManagerTests
{
    [Fact]
    public void ThreatIdAcceptsBothGuidFormats()
    {
        var id = Guid.NewGuid();

        Assert.True(FirewallManager.TryParseThreatId(id.ToString("N"), out var fromN));
        Assert.Equal(id, fromN);
        Assert.True(FirewallManager.TryParseThreatId(id.ToString("D"), out var fromD));
        Assert.Equal(id, fromD);
        Assert.False(FirewallManager.TryParseThreatId("no-es-un-guid", out _));
        Assert.False(FirewallManager.TryParseThreatId(string.Empty, out _));
    }

    [Theory]
    [InlineData("N")]
    [InlineData("D")]
    public void DescriptionIsRecognizedRegardlessOfGuidFormat(string format)
    {
        var id = Guid.NewGuid();
        var description = $"AEGIS Guard - {id.ToString(format)} - riesgo 87";

        Assert.True(FirewallManager.IsThreatRuleDescription(description, id.ToString("N")));
        Assert.True(FirewallManager.IsThreatRuleDescription(description, id.ToString("D")));
    }

    [Fact]
    public void UnrelatedDescriptionsAreNotRecognized()
    {
        var id = Guid.NewGuid();

        Assert.False(FirewallManager.IsThreatRuleDescription("Regla manual del usuario", id.ToString("N")));
        Assert.False(FirewallManager.IsThreatRuleDescription("AEGIS Guard - otro - riesgo 10", id.ToString("N")));
        Assert.False(FirewallManager.IsThreatRuleDescription(null, id.ToString("N")));
    }
}
