using Aegis.Service;
using Xunit;

namespace Aegis.Checks;

public class AegisProfilePathsTests
{
    [Fact]
    public void UserDirectoriesUsesRegisteredInteractiveProfile()
    {
        if (!OperatingSystem.IsWindows()) return;
        var sid = System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value;
        if (string.IsNullOrWhiteSpace(sid)) return;
        var previous = Environment.GetEnvironmentVariable("AEGIS_UI_USER_SID");
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        try
        {
            Environment.SetEnvironmentVariable("AEGIS_UI_USER_SID", sid);
            var dirs = AegisProfilePaths.UserDirectories();
            Assert.Contains(Path.Combine(profile, "Desktop"), dirs, StringComparer.OrdinalIgnoreCase);
            Assert.Contains(Path.Combine(profile, "Documents"), dirs, StringComparer.OrdinalIgnoreCase);
            Assert.Contains(Path.Combine(profile, "Downloads"), dirs, StringComparer.OrdinalIgnoreCase);
            Assert.DoesNotContain(dirs, d => d.Contains("systemprofile", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            Environment.SetEnvironmentVariable("AEGIS_UI_USER_SID", previous);
        }
    }
}
