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

            // Cuando el servicio se ejecuta como LocalSystem, la UI abre el
            // proceso con el usuario interactive. El instalador registra ese SID
            // y Solo se le concede lectura sobre el token y archivos de estado.
            var uiSid = Environment.GetEnvironmentVariable("AEGIS_UI_USER_SID");
            if (!string.IsNullOrWhiteSpace(uiSid))
            {
                try
                {
                    security.AddAccessRule(new FileSystemAccessRule(
                        new SecurityIdentifier(uiSid), FileSystemRights.ReadAndExecute, AccessControlType.Allow));
                }
                catch (ArgumentException)
                {
                    // SID invalido: no ampliar permisos; la UI informara del error.
                }
            }

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
