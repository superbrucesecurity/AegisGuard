using Microsoft.Win32;
using System.Security;
using System.Security.Principal;

namespace Aegis.Service;

/// <summary>
/// Rutas del usuario interactivo cuando el servicio se ejecuta como
/// LocalSystem. Sin esta resolución, el perfil de SYSTEM no contiene Desktop,
/// Documentos ni Descargas y los watchers/canarios quedarían degradados.
/// </summary>
public static class AegisProfilePaths
{
    public static IReadOnlyList<string> UserDirectories()
    {
        var userProfile = ResolveInteractiveProfile();
        var profile = string.IsNullOrWhiteSpace(userProfile) ? ResolveProfileDirectory() : userProfile;
        var candidates = new[]
        {
            Path.Combine(profile, "Desktop"),
            Path.Combine(profile, "Documents"),
            Path.Combine(profile, "Downloads"),
            Path.GetTempPath()
        };

        return candidates
            .Where(p => !string.IsNullOrWhiteSpace(p) && Directory.Exists(p))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static string ResolveProfileDirectory()
    {
        try { return Environment.GetFolderPath(Environment.SpecialFolder.UserProfile); }
        catch { return string.Empty; }
    }

    private static string? ResolveInteractiveProfile()
    {
        if (!OperatingSystem.IsWindows()) return null;
        var sid = Environment.GetEnvironmentVariable("AEGIS_UI_USER_SID");
        if (string.IsNullOrWhiteSpace(sid)) return null;
        try
        {
            // Validar el SID antes de usarlo como parte de una clave de registro.
            _ = new SecurityIdentifier(sid);
            using var key = Registry.LocalMachine.OpenSubKey(
                $@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}");
            return key?.GetValue("ProfileImagePath") as string;
        }
        catch (Exception ex) when (ex is ArgumentException or SecurityException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
