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

    /// <summary>
    /// Detecta la muestra EICAR aunque el patrón cruce dos lecturas. Expuesto
    /// para verificar ese caso límite sin escribir la muestra en disco, donde
    /// otros productos de seguridad pueden bloquearla legítimamente.
    /// </summary>
    public sealed class EicarScanner
    {
        private readonly byte[] _window = new byte[128 * 1024 + EicarSampleBytes.Length];
        private int _tail;
        public bool Found { get; private set; }

        public void Scan(ReadOnlySpan<byte> chunk)
        {
            if (Found || chunk.IsEmpty) return;
            var combined = _tail + chunk.Length;
            chunk.CopyTo(_window.AsSpan(_tail));
            Found = ContainsEicarSample(_window.AsSpan(0, combined));
            var keep = Math.Min(EicarSampleBytes.Length - 1, combined);
            if (keep > 0) _window.AsSpan(combined - keep, keep).CopyTo(_window);
            _tail = keep;
        }
    }

    public async Task<(string sha256, long length, bool eicar)> HashAsync(string path, CancellationToken ct = default)
    {
        using var sha = SHA256.Create();
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 128 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        var buffer = ArrayPool<byte>.Shared.Rent(128 * 1024);
        var scanner = new EicarScanner();
        long total = 0;
        try
        {
            int read;
            while ((read = await fs.ReadAsync(buffer.AsMemory(0, 128 * 1024), ct).ConfigureAwait(false)) > 0)
            {
                total += read;
                sha.TransformBlock(buffer, 0, read, null, 0);
                scanner.Scan(buffer.AsSpan(0, read));
            }
            sha.TransformFinalBlock([], 0, 0);
            return (Convert.ToHexString(sha.Hash!).ToLowerInvariant(), total, scanner.Found);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static readonly HashSet<string> SignableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".msi", ".msp", ".scr", ".com", ".cpl", ".ocx", ".drv"
    };

    /// <summary>
    /// Clasifica el código devuelto por WinVerifyTrust. Se mantiene público y
    /// puro para poder verificar todos los estados con tests sin depender de
    /// ficheros firmados ni de la infraestructura de certificados del equipo.
    /// </summary>
    public static SignatureStatus ClassifyWinTrustStatus(int status)
    {
        var code = unchecked((uint)status);
        if (code == 0) return SignatureStatus.SignedTrusted;

        // Sin firma o tipo de fichero sin proveedor de subject interface.
        if (code is 0x800B0100 or 0x800B0003 or 0x800B0001 or 0x800B0002)
            return SignatureStatus.Unsigned;

        // Fallos de validación reales de la firma o de la cadena de confianza.
        if (s_untrustedCodes.Contains(code)) return SignatureStatus.SignedUntrusted;

        // La cadena no se pudo comprobar: no es una prueba de maldad.
        // CERT_E_REVOCATION_FAILURE y CRYPT_E_REVOCATION_OFFLINE.
        if (code is 0x800B010E or 0x80092012)
            return SignatureStatus.ChainNotVerifiable;

        // CRYPT_E_FILE_ERROR, ERROR_FILE_NOT_FOUND, ERROR_ACCESS_DENIED,
        // E_INVALIDARG y cualquier otro código de infraestructura: desconocido.
        return SignatureStatus.Unknown;
    }

    private static readonly HashSet<uint> s_untrustedCodes =
    [
        0x800B0004, // TRUST_E_SUBJECT_NOT_TRUSTED
        0x800B0101, // CERT_E_EXPIRED
        0x800B0102, // CERT_E_VALIDITYPERIODNESTING
        0x800B0103, // CERT_E_ROLE
        0x800B0104, // CERT_E_PATHLENCONST
        0x800B0105, // CERT_E_CRITICAL
        0x800B0106, // CERT_E_PURPOSE
        0x800B0107, // CERT_E_ISSUERCHAINING
        0x800B0108, // CERT_E_MALFORMED
        0x800B0109, // CERT_E_UNTRUSTEDROOT
        0x800B010A, // CERT_E_CHAINING
        0x800B010B, // CERT_E_UNTRUSTEDTESTROOT
        0x800B010C, // CERT_E_REVOKED
        0x800B010F, // CERT_E_CN_NO_MATCH
        0x800B0110, // CERT_E_WRONG_USAGE
        0x800B0111, // TRUST_E_EXPLICIT_DISTRUST
        0x800B0112, // CERT_E_UNTRUSTEDCA
        0x800B0113, // CERT_E_INVALID_POLICY
        0x800B0114, // CERT_E_INVALID_NAME
        0x80096010  // TRUST_E_BAD_DIGEST
    ];

    public SignatureStatus VerifySignature(string path)
    {
        if (!SignableExtensions.Contains(Path.GetExtension(path)))
            return SignatureStatus.NotApplicable;

        var fileInfo = default(WINTRUST_FILE_INFO);
        var verifyData = default(WINTRUST_DATA);
        var action = WinTrustActionGenericVerifyV2;
        try
        {
            fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                pcwszFilePath = Marshal.StringToHGlobalUni(path)
            };
            verifyData = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = WtdUiNone,
                fdwRevocationChecks = WtdRevocationCheckNone,
                dwUnionChoice = WtdChoiceFile,
                pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>()),
                // WTD_STATEACTION_VERIFY es 1 (0 era WTD_STATEACTION_IGNORE).
                dwStateAction = WtdStateActionVerify,
                // Solo caché local: la decisión no depende de Internet.
                dwProvFlags = WtdCacheOnlyUrlRetrieval | WtdRevocationCheckChainExcludeRoot | WtdDisableMd2Md4,
                dwUIContext = WtdUiContextExecute
            };
            Marshal.StructureToPtr(fileInfo, verifyData.pFile, false);
            return ClassifyWinTrustStatus(WinVerifyTrust(IntPtr.Zero, ref action, ref verifyData));
        }
        catch
        {
            return SignatureStatus.Unknown;
        }
        finally
        {
            // Toda llamada con WTD_STATEACTION_VERIFY exige una llamada posterior
            // con WTD_STATEACTION_CLOSE y el mismo handle, incluso si falló.
            if (verifyData.hWVTStateData != IntPtr.Zero)
            {
                try
                {
                    var closeData = new WINTRUST_DATA
                    {
                        cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                        dwStateAction = WtdStateActionClose,
                        hWVTStateData = verifyData.hWVTStateData
                    };
                    WinVerifyTrust(IntPtr.Zero, ref action, ref closeData);
                }
                catch
                {
                    // La limpieza es best-effort: nunca sustituye al resultado.
                }
                verifyData.hWVTStateData = IntPtr.Zero;
            }
            if (verifyData.pFile != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(verifyData.pFile);
                verifyData.pFile = IntPtr.Zero;
            }
            if (fileInfo.pcwszFilePath != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(fileInfo.pcwszFilePath);
                fileInfo.pcwszFilePath = IntPtr.Zero;
            }
        }
    }

    private const uint WtdUiNone = 2;
    private const uint WtdRevocationCheckNone = 0;
    private const uint WtdChoiceFile = 1;
    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;
    private const uint WtdUiContextExecute = 0;
    private const uint WtdCacheOnlyUrlRetrieval = 0x00001000;
    private const uint WtdRevocationCheckChainExcludeRoot = 0x00000080;
    private const uint WtdDisableMd2Md4 = 0x00002000;

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
