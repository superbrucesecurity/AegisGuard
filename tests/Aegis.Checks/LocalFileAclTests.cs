using System.Security.AccessControl;
using System.Security.Principal;
using Aegis.Service;

namespace Aegis.Checks;

public class LocalFileAclTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "aegis-acl-" + Guid.NewGuid().ToString("N"));

    public LocalFileAclTests() => Directory.CreateDirectory(_root);

    [Fact]
    public void ElEstadoNoEsLegiblePorCualquierUsuario()
    {
        if (!OperatingSystem.IsWindows()) return;

        var file = Path.Combine(_root, "config.json");
        File.WriteAllText(file, "{}");
        Assert.True(LocalFileAcl.Restrict(file));
        AssertSinWorld(WindowsIdentity.GetCurrent().User,
            new FileInfo(file).GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier)));

        Assert.True(LocalFileAcl.RestrictDirectory(_root));
        AssertSinWorld(WindowsIdentity.GetCurrent().User,
            new DirectoryInfo(_root).GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier)));
    }

    [Fact]
    public void LaReparacionDelArbolNoSigueEnlaces()
    {
        if (!OperatingSystem.IsWindows()) return;

        var child = Path.Combine(_root, "quarantine");
        Directory.CreateDirectory(child);
        var file = Path.Combine(child, "item.bin");
        File.WriteAllBytes(file, new byte[] { 1, 2, 3 });

        LocalFileAcl.RestrictTree(_root);

        AssertSinWorld(WindowsIdentity.GetCurrent().User,
            new FileInfo(file).GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier)));
    }

    private static void AssertSinWorld(SecurityIdentifier? currentUser, AuthorizationRuleCollection rules)
    {
        var world = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
        Assert.DoesNotContain(rules.Cast<FileSystemAccessRule>(), r =>
            r.AccessControlType == AccessControlType.Allow && r.IdentityReference == world);

        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var allowed = rules.Cast<FileSystemAccessRule>()
            .Where(r => r.AccessControlType == AccessControlType.Allow)
            .Select(r => r.IdentityReference)
            .ToList();
        Assert.Contains(system, allowed);
        Assert.Contains(admins, allowed);
        if (currentUser is not null) Assert.Contains(currentUser, allowed);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            try { Directory.Delete(_root, true); }
            catch (IOException) { /* mejor esfuerzo */ }
        }
    }
}
