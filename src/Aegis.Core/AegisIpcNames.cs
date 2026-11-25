using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace Aegis.Core;

/// <summary>
/// Nombre de la tubería privilegiada, derivado del SID del usuario autorizado.
/// Servicio y UI usan exactamente la misma función: no hay un nombre editable
/// por configuración ni un secreto compartido.
/// </summary>
public static class AegisIpcNames
{
    public static string PrivilegedPipe(string sid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sid);
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sid)))[..16].ToLowerInvariant();
        return $"aegisguard-{hash}-privileged";
    }

    /// <summary>
    /// SID autorizado por la instalación. El instalador lo escribe en
    /// AEGIS_UI_USER_SID; si no está definido (arranque manual) se usa el
    /// usuario actual. Servicio y UI deben llamar a esta misma función: UAC
    /// puede elevar con una cuenta distinta y eso no debe cambiar el pipe.
    /// </summary>
    public static string AuthorizedUserSid()
    {
        var configured = Environment.GetEnvironmentVariable("AEGIS_UI_USER_SID");
        if (!string.IsNullOrWhiteSpace(configured)) return configured;
        if (OperatingSystem.IsWindows())
        {
            var current = WindowsIdentity.GetCurrent().User?.Value;
            if (!string.IsNullOrWhiteSpace(current)) return current;
        }
        return "aegis-console";
    }

    /// <summary>
    /// SID que el servicio exige para atender la tubería. A diferencia de
    /// AuthorizedUserSid(), no admite el fallback al usuario actual: un servicio
    /// gestionado por SCM debe tener el SID del usuario autorizado escrito por
    /// el instalador. Tampoco concede acceso a todo el grupo Interactive.
    /// </summary>
    public static string RequireConfiguredAuthorizedSid()
    {
        var configured = Environment.GetEnvironmentVariable("AEGIS_UI_USER_SID");
        if (string.IsNullOrWhiteSpace(configured))
            throw new InvalidOperationException("AEGIS_UI_USER_SID no está configurado; el canal IPC no puede iniciarse.");
        if (!OperatingSystem.IsWindows()) return configured;
        try
        {
            return new SecurityIdentifier(configured).Value;
        }
        catch (ArgumentException ex)
        {
            throw new InvalidOperationException("AEGIS_UI_USER_SID no es un SID válido; el canal IPC no puede iniciarse.", ex);
        }
    }

    public static string PrivilegedPipeForAuthorizedUser() => PrivilegedPipe(AuthorizedUserSid());
}
