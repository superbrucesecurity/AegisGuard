using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace Aegis.Service;

/// <summary>
/// Lee la identidad real del proceso conectado a la tubería. El cliente no
/// puede influence estos valores: se obtienen de su token de Windows.
/// </summary>
public static class NativeClientIdentity
{
    // SECURITY_MANDATORY_*_RID definidos en winnt.h.
    public const int LowIntegrityRid = 0x1000;
    public const int MediumIntegrityRid = 0x2000;
    public const int HighIntegrityRid = 0x3000;
    public const int SystemIntegrityRid = 0x4000;

    private const uint ProcessQueryLimitedInformation = 0x1000;
    // TOKEN_QUERY | TOKEN_DUPLICATE: se necesita duplicar el token primario
    // para comprobar pertenencia a grupos con CheckTokenMembership.
    private const uint TokenQueryAndDuplicate = 0x000A;
    private const int SecurityImpersonation = 2;
    private const int TokenUser = 1;
    private const int TokenElevationInformation = 18;
    private const int TokenIntegrityLevel = 25;

    private static readonly SecurityIdentifier InteractiveSid =
        new(WellKnownSidType.InteractiveSid, null);
    private static readonly SecurityIdentifier AdministratorsSid =
        new(WellKnownSidType.BuiltinAdministratorsSid, null);

    public static ClientIdentity? FromPipe(SafePipeHandle pipe)
    {
        if (!OperatingSystem.IsWindows()) return null;
        if (!GetNamedPipeClientProcessId(pipe, out var pid) || pid == 0)
            return null;

        using var process = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (process is null || process.IsInvalid || process.IsClosed) return null;
        if (!OpenProcessToken(process, TokenQueryAndDuplicate, out var token) || token.IsInvalid || token.IsClosed)
            return null;
        using (token)
        {
            var userSid = ReadSid(token, TokenUser);
            if (userSid is null) return null;
            var integritySid = ReadSid(token, TokenIntegrityLevel);
            var integrity = integritySid is null ? 0 : LastRid(integritySid);
            var elevationValue = ReadInt(token, TokenElevationInformation);
            var elevation = elevationValue.HasValue
                ? (TokenElevationType)elevationValue.Value
                : TokenElevationType.Default;

            var isAdmin = IsMember(token, AdministratorsSid);
            var isInteractive = IsMember(token, InteractiveSid);
            return new ClientIdentity(
                checked((int)pid), userSid, integrity, elevation, isAdmin, isInteractive);
        }
    }

    private static bool IsMember(SafeAccessTokenHandle primaryToken, SecurityIdentifier sid)
    {
        // CheckTokenMembership exige un token de suplantación cuando se le
        // pasa un handle explícito. El token del proceso es primario.
        if (!DuplicateToken(primaryToken, SecurityImpersonation, out var token) ||
            token.IsInvalid || token.IsClosed)
            return false;
        using (token)
        {
            var bytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(bytes, 0);
            var pinned = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try
            {
                return CheckTokenMembership(token, pinned.AddrOfPinnedObject(), out var member) && member;
            }
            finally
            {
                pinned.Free();
            }
        }
    }

    private static string? ReadSid(SafeAccessTokenHandle token, int informationClass)
    {
        if (!TryGetTokenInformationLength(token, informationClass, out var length) || length == 0)
            return null;
        var buffer = Marshal.AllocHGlobal(checked((int)length));
        try
        {
            if (!GetTokenInformation(token, informationClass, buffer, length, out _)) return null;
            var sidPointer = Marshal.ReadIntPtr(buffer);
            if (sidPointer == IntPtr.Zero) return null;
            return new SecurityIdentifier(sidPointer).Value;
        }
        catch (Exception ex) when (ex is ArgumentException or System.Security.SecurityException)
        {
            return null;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static int? ReadInt(SafeAccessTokenHandle token, int informationClass)
    {
        if (!TryGetTokenInformationLength(token, informationClass, out var length) || length < 4)
            return null;
        var buffer = Marshal.AllocHGlobal(checked((int)length));
        try
        {
            if (!GetTokenInformation(token, informationClass, buffer, length, out _)) return null;
            return Marshal.ReadInt32(buffer);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static bool TryGetTokenInformationLength(SafeAccessTokenHandle token, int informationClass, out uint length)
    {
        // ERROR_INSUFFICIENT_BUFFER es la respuesta esperada cuando se consulta
        // el tamaño con una longitud cero.
        var ok = GetTokenInformation(token, informationClass, IntPtr.Zero, 0, out length);
        return !ok || length > 0;
    }

    private static int LastRid(string sid)
    {
        var parts = sid.Split('-');
        return parts.Length > 1 && int.TryParse(parts[^1], out var rid) ? rid : 0;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle hNamedPipe, out uint clientProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(
        uint dwDesiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
        uint dwProcessId);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(
        SafeProcessHandle ProcessHandle,
        uint DesiredAccess,
        out SafeAccessTokenHandle TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(
        SafeAccessTokenHandle TokenHandle,
        int TokenInformationClass,
        IntPtr TokenInformation,
        uint TokenInformationLength,
        out uint ReturnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateToken(
        SafeAccessTokenHandle ExistingTokenHandle,
        int ImpersonationLevel,
        out SafeAccessTokenHandle DuplicateTokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CheckTokenMembership(
        SafeAccessTokenHandle TokenHandle,
        IntPtr SidToCheck,
        [MarshalAs(UnmanagedType.Bool)] out bool IsMember);
}
