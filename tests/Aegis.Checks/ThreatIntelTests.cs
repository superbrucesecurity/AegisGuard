using System.Text.Json;
using Aegis.Core;

namespace Aegis.Tests;

public sealed class ThreatIntelTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "aegis-intel-" + Guid.NewGuid().ToString("N"));

    public ThreatIntelTests() => Directory.CreateDirectory(_root);

    [Fact]
    public void LoadsAndMatchesHashesDomainsAndIps()
    {
        var path = Path.Combine(_root, "threat-intel.json");
        File.WriteAllText(path, JsonSerializer.Serialize(new
        {
            maliciousSha256 = new[] { "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F" },
            maliciousDomains = new[] { "evil.example" },
            maliciousIps = new[] { "203.0.113.9" }
        }));

        var intel = new ThreatIntel();
        intel.Load(path);

        Assert.Equal(1, intel.HashCount);
        Assert.Equal(1, intel.DomainCount);
        Assert.Equal(1, intel.IpCount);
        Assert.True(intel.IsMaliciousHash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"));
        Assert.True(intel.IsMaliciousDomain("sub.evil.example"));
        Assert.False(intel.IsMaliciousDomain("evil.example.invalid"));
        Assert.True(intel.IsMaliciousIp("203.0.113.9"));
        Assert.False(intel.IsMaliciousIp("198.51.100.2"));
    }

    [Fact]
    public void BundledListsContainNoInventedIndicators()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "rules", "threat-intel.json");
        var intel = new ThreatIntel();
        intel.Load(path);

        Assert.True(intel.HashCount >= 1);
        Assert.Equal(0, intel.DomainCount);
        Assert.Equal(0, intel.IpCount);
        Assert.False(intel.IsMaliciousDomain("evil.example"));
        Assert.False(intel.IsMaliciousIp("203.0.113.9"));
    }

    [Fact]
    public void FirewallRuleNameUsesProductPrefixAndIsBounded()
    {
        var manager = new FirewallManager();
        var name = manager.BuildRuleName(new FirewallRuleSpec
        {
            Block = true,
            ApplicationPath = @"C:\Temp\programa.exe",
            RemoteAddresses = "203.0.113.9",
            RemotePort = 4444
        });

        Assert.StartsWith(manager.ProductPrefix, name, StringComparison.Ordinal);
        Assert.Contains("BLOCK", name, StringComparison.Ordinal);
        Assert.Contains("programa.exe", name, StringComparison.Ordinal);
        Assert.True(name.Length <= 250);
    }

    [Fact]
    public void QuarantinePolicyRejectsUnsafePaths()
    {
        Assert.False(PathPolicy.IsQuarantineSafe("ruta-relativa"));
        Assert.False(PathPolicy.IsQuarantineSafe(@"C:\"));
        if (OperatingSystem.IsWindows())
            Assert.False(PathPolicy.IsQuarantineSafe(@"C:\Program Files\App\archivo.dll"));
        Assert.True(PathPolicy.IsQuarantineSafe(Path.Combine(_root, "archivo.txt")));
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, true); }
        catch (IOException) { /* ignorar bloqueo temporal */ }
    }
}
