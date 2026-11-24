using System.Buffers;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace Aegis.Core;

[SupportedOSPlatform("windows")]
public sealed class FileInspector
{
    // Compuesta en tiempo de compilación a partir de bytes: un archivo con la
    // cadena literal puede ser bloqueado por el propio antivirus del equipo.
    /// <summary>
    /// Muestra EICAR estándar compuesta en tiempo de compilación a partir de
    /// bytes. Se expone para la prueba automática del motor sin escribir la
    /// cadena literal en el código servido.
    /// </summary>
    public static readonly byte[] EicarSampleBytes =
    [
        0x58, 0x35, 0x4F, 0x21, 0x50, 0x25, 0x40, 0x41, 0x50, 0x5B, 0x34, 0x5C, 0x50, 0x5A,
        0x58, 0x35, 0x34, 0x28, 0x50, 0x5E, 0x29, 0x37, 0x43, 0x43, 0x29, 0x37, 0x7D, 0x24,
        0x45, 0x49, 0x43, 0x41, 0x52, 0x2D, 0x53, 0x54, 0x41, 0x4E, 0x44, 0x41, 0x52, 0x44,
        0x2D, 0x41, 0x4E, 0x54, 0x49, 0x56, 0x49, 0x52, 0x55, 0x53, 0x2D, 0x54, 0x45, 0x53,
        0x54, 0x2D, 0x46, 0x49, 0x4C, 0x45, 0x21, 0x24, 0x48, 0x2B, 0x48, 0x2A
    ];

    /// <summary>
    /// Comprueba la firma EICAR sobre bytes ya leídos. Separarla de la E/S
    /// permite verificar la detección sin escribir una muestra en disco, que
    /// otros productos de seguridad pueden bloquear legítimamente.
    /// </summary>
    public static bool ContainsEicarSample(ReadOnlySpan<byte> data) => data.IndexOf(EicarSampleBytes) >= 0;

    public async Task<(string sha256, long length, bool eicar)> HashAsync(string path, CancellationToken ct = default)
    {
        using var sha = SHA256.Create();
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 128 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        var buffer = ArrayPool<byte>.Shared.Rent(128 * 1024);
        long total = 0;
        var eicar = false;
        var head = new byte[EicarSampleBytes.Length];
        var headLength = 0;
        try
        {
            int read;
            while ((read = await fs.ReadAsync(buffer.AsMemory(0, buffer.Length), ct).ConfigureAwait(false)) > 0)
            {
                total += read;
                sha.TransformBlock(buffer, 0, read, null, 0);
                if (headLength < head.Length)
                {
                    var take = Math.Min(read, head.Length - headLength);
                    Buffer.BlockCopy(buffer, 0, head, headLength, take);
                    headLength += take;
                }
            }
            sha.TransformFinalBlock([], 0, 0);
            eicar = ContainsEicarSample(head.AsSpan(0, headLength));
            return (Convert.ToHexString(sha.Hash!).ToLowerInvariant(), total, eicar);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    public SignatureStatus VerifySignature(string path)
    {
        if (!Path.GetExtension(path).Equals(".exe", StringComparison.OrdinalIgnoreCase) &&
            !Path.GetExtension(path).Equals(".dll", StringComparison.OrdinalIgnoreCase) &&
            !Path.GetExtension(path).Equals(".sys", StringComparison.OrdinalIgnoreCase) &&
            !Path.GetExtension(path).Equals(".msi", StringComparison.OrdinalIgnoreCase))
        {
            return SignatureStatus.NotApplicable;
        }

        var fileInfo = default(WINTRUST_FILE_INFO);
        var data = default(WINTRUST_DATA);
        try
        {
            fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                pcwszFilePath = Marshal.StringToHGlobalUni(path)
            };
            data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = WtdUiNone,
                fdwRevocationChecks = WtdRevocationCheckWholeChain,
                dwUnionChoice = WtdChoiceFile,
                pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>()),
                dwStateAction = WtdStateActionVerify,
                dwProvFlags = WtdUseSafeDllSearch
            };
            Marshal.StructureToPtr(fileInfo, data.pFile, false);
            var action = WinTrustActionGenericVerifyV2;
            var result = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            var code = unchecked((uint)result);

            // Solo los errores de firma se consideran "firma no válida"; un error
            // de API (CRYPT_E_FILE_ERROR, E_INVALIDARG, ...) es desconocido.
            if (code == 0) return SignatureStatus.SignedTrusted;
            if (code is 0x800B0100 or 0x800B0003) return SignatureStatus.Unsigned;
            if (code == 0x80092010 || (code & 0xFFFF0000) == 0x800B0000) return SignatureStatus.SignedUntrusted;
            return SignatureStatus.Unknown;
        }
        catch
        {
            return SignatureStatus.Unknown;
        }
        finally
        {
            if (data.pFile != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(data.pFile);
                data.pFile = IntPtr.Zero;
            }
            if (fileInfo.pcwszFilePath != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(fileInfo.pcwszFilePath);
                fileInfo.pcwszFilePath = IntPtr.Zero;
            }
        }
    }

    private const uint WtdUiNone = 2;
    private const uint WtdRevocationCheckWholeChain = 1;
    private const uint WtdChoiceFile = 1;
    private const uint WtdStateActionVerify = 0;
    private const uint WtdUseSafeDllSearch = 0x00000100;

    private static readonly Guid WinTrustActionGenericVerifyV2 = new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

    [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
    }
}
