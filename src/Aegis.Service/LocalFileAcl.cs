using System.Security.AccessControl;
using System.Security.Principal;

namespace Aegis.Service;

/// <summary>
/// ACL mínima para el estado local: SYSTEM, administradores y el usuario que
/// ejecuta el servicio. La UI ya no lee archivos directamente: obtiene datos
/// por HTTP local y ejecuta cambios por IPC, por lo que no necesita permisos
/// sobre este árbol. Se aplica al crear y al reparar permisos.
/// </summary>
public static class LocalFileAcl
{
    public static bool Restrict(string path)
    {
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            var security = new FileSecurity();
            AddRules(security);
            new FileInfo(path).SetAccessControl(security);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                                       InvalidOperationException or ArgumentException)
        {
            return false;
        }
    }

    public static bool RestrictDirectory(string path)
    {
        if (!OperatingSystem.IsWindows()) return false;
        var full = Path.GetFullPath(path);
        if (string.Equals(full, Path.GetPathRoot(full), StringComparison.OrdinalIgnoreCase)) return false;
        try
        {
            var security = new DirectorySecurity();
            AddRules(security);
            new DirectoryInfo(full).SetAccessControl(security);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                                       InvalidOperationException or ArgumentException)
        {
            return false;
        }
    }

    /// <summary>
    /// Repara ACL heredadas de versiones anteriores, donde el usuario
    /// interactivo tenía acceso directo a configuración, cuarentena e historial.
    /// </summary>
    public static void RestrictTree(string root)
    {
        if (!OperatingSystem.IsWindows() || !Directory.Exists(root)) return;
        var options = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = true,
            AttributesToSkip = FileAttributes.ReparsePoint
        };
        try
        {
            RestrictDirectory(root);
            var directory = new DirectoryInfo(root);
            foreach (var child in directory.EnumerateDirectories("*", options))
                RestrictDirectory(child.FullName);
            foreach (var file in directory.EnumerateFiles("*", options))
                Restrict(file.FullName);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            // fallo parcial: se registrará en el estado real del servicio
        }
    }

    private static void AddRules(FileSystemSecurity security)
    {
        // No se cambia el propietario: hacerlo exigiría SeTakeOwnership y
        // fallaría cuando el servicio se ejecuta como usuario estándar.
        security.SetSecurityDescriptorSddlForm("D:");
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            FileSystemRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            FileSystemRights.FullControl, AccessControlType.Allow));
        var user = WindowsIdentity.GetCurrent().User;
        if (user is not null)
            security.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.FullControl, AccessControlType.Allow));
    }
}
