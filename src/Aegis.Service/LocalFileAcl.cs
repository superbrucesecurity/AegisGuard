using System.Security.AccessControl;
using System.Security.Principal;

namespace Aegis.Service;

/// <summary>
/// ACL mínima para archivos de estado local: SYSTEM, administradores y el
/// usuario que ejecuta el servicio. Se aplica al crear y al reparar permisos.
/// </summary>
public static class LocalFileAcl
{
    public static bool Restrict(string path)
    {
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            var security = new FileSecurity();
            // No se cambia el propietario: hacerlo exigiría SeTakeOwnership
            // y fallaría cuando el servicio se ejecuta como usuario estándar.
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

            new FileInfo(path).SetAccessControl(security);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                                       InvalidOperationException or ArgumentException)
        {
            return false;
        }
    }
}
