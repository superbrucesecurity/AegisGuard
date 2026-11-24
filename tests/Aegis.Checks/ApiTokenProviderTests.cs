using System.Security.AccessControl;
using System.Security.Principal;
using Aegis.Service;

namespace Aegis.Tests;

public sealed class ApiTokenProviderTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "aegis-token-" + Guid.NewGuid().ToString("N"));

    public ApiTokenProviderTests() => Directory.CreateDirectory(_root);

    [Fact]
    public void TokenIsReusedAndAclIsRestricted()
    {
        var provider = new ApiTokenProvider(_root);
        provider.LoadOrCreate();
        var token = provider.Token;
        Assert.True(token.Length >= 32);

        var second = new ApiTokenProvider(_root);
        second.LoadOrCreate();
        Assert.Equal(token, second.Token);

        if (!OperatingSystem.IsWindows()) return;
        var rules = new FileInfo(Path.Combine(_root, "ui-token")).GetAccessControl()
            .GetAccessRules(true, true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>().ToList();
        var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
        Assert.DoesNotContain(rules, r => r.AccessControlType == AccessControlType.Allow && r.IdentityReference == everyone);
    }

    [Fact]
    public void CorruptTokenIsRegeneratedWithoutBlockingStartup()
    {
        var file = Path.Combine(_root, "ui-token");
        File.WriteAllText(file, "token-truncado");

        var provider = new ApiTokenProvider(_root);
        provider.LoadOrCreate();

        Assert.Equal(44, provider.Token.Length);
        Assert.Equal(Convert.ToBase64String(new byte[32]).Length, provider.Token.Length);
        Assert.NotEqual("token-truncado", provider.Token);
        Assert.True(provider.Matches("Bearer " + provider.Token));
        Assert.Contains(Directory.EnumerateFiles(_root, "ui-token.invalid-*"),
            p => File.ReadAllText(p) == "token-truncado");
    }

    [Fact]
    public void AuthorizationIsComparedInConstantTime()
    {
        var provider = new ApiTokenProvider(_root);
        provider.LoadOrCreate();

        Assert.True(provider.Matches("Bearer " + provider.Token));
        Assert.False(provider.Matches(null));
        Assert.False(provider.Matches(string.Empty));
        Assert.False(provider.Matches("Basic " + provider.Token));
        Assert.False(provider.Matches("Bearer " + provider.Token + "x"));
        Assert.False(provider.Matches("Bearer " + provider.Token[..^1]));

        var restarted = new ApiTokenProvider(_root);
        restarted.LoadOrCreate();
        Assert.True(restarted.Matches("Bearer " + provider.Token));
    }

    [Fact]
    public void WeakAclOnExistingTokenIsRepaired()
    {
        var file = Path.Combine(_root, "ui-token");
        File.WriteAllText(file, Convert.ToBase64String(new byte[32]));
        if (!OperatingSystem.IsWindows()) return;

        var weak = new FileSecurity();
        weak.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.WorldSid, null),
            FileSystemRights.FullControl, AccessControlType.Allow));
        new FileInfo(file).SetAccessControl(weak);

        new ApiTokenProvider(_root).LoadOrCreate();

        var rules = new FileInfo(file).GetAccessControl()
            .GetAccessRules(true, true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>().ToList();
        var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
        Assert.DoesNotContain(rules, r => r.AccessControlType == AccessControlType.Allow && r.IdentityReference == everyone);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, true); }
        catch (IOException) { /* bloqueo temporal del sistema de archivos */ }
    }
}
