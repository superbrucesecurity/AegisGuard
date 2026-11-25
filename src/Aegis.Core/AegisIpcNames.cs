using System.Security.Cryptography;
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
}
