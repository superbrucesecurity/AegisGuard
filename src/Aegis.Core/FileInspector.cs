using System.Buffers;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace Aegis.Core;

[SupportedOSPlatform("windows")]
public sealed class FileInspector
{
    private const string EicarSignature = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    public async Task<(string sha256, long length, bool eicar)> HashAsync(string path, CancellationToken ct = default)
    {
        using var sha = SHA256.Create();
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 128 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        var buffer = ArrayPool<byte>.Shared.Rent(128 * 1024);
        long total = 0;
        var eicar = false;
        var head = new byte[EicarSignature.Length];
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
            eicar = Encoding.ASCII.GetString(head, 0, headLength).Contains(EicarSignature, StringComparison.Ordinal);
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

        try
        {
            var fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                pcwszFilePath = Marshal.StringToHGlobalUni(path)
            };
            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = WtdUiNone,
                fdwRevocationChecks = WtdRevocationCheckNone,
                dwUnionChoice = WtdChoiceFile,
                pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>()),
                dwStateAction = WtdStateActionVerify,
                dwProvFlags = WtdUseSafeDllSearch
            };
            Marshal.StructureToPtr(fileInfo, data.pFile, false);
            var action = WinTrustActionGenericVerifyV2;
            var result = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            Marshal.FreeHGlobal(data.pFile);
            Marshal.FreeHGlobal(fileInfo.pcwszFilePath);

            return result switch
            {
                0 => SignatureStatus.SignedTrusted,
                unchecked((int)0x800B0100) or unchecked((int)0x800B0003) => SignatureStatus.Unsigned,
                _ => SignatureStatus.SignedUntrusted
            };
        }
        catch
        {
            return SignatureStatus.Unknown;
        }
    }

    private const uint WtdUiNone = 2;
    private const uint WtdRevocationCheckNone = 0;
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
