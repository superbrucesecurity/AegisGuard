using System.Buffers.Binary;
using System.Globalization;
using System.Text;

namespace Aegis.Core;

/// <summary>
/// Analizador estructural de cabeceras PE/COFF. Trabaja sobre una copia ya
/// leída del fichero: no abre rutas, no ejecuta código y no extrae nada a disco.
/// Una cabecera malformada es evidencia de análisis incompleto, no de malware.
/// </summary>
public sealed class PeInspector
{
    private const ushort DosMagic = 0x5A4D;
    private const uint PeSignature = 0x00004550; // "PE\0\0"
    private const ushort Pe32Magic = 0x010B;
    private const ushort Pe32PlusMagic = 0x020B;

    private const uint SectionCode = 0x00000020;
    private const uint SectionExecute = 0x20000000;
    private const uint SectionWrite = 0x80000000;

    private const ushort DllHighEntropyVa = 0x0020;
    private const ushort DllDynamicBase = 0x0040;
    private const ushort DllNoSeh = 0x0400;
    private const ushort DllNxCompatible = 0x0100;
    private const ushort DllGuardCf = 0x4000;

    /// <summary>Analiza los primeros bytes de un fichero y devuelve evidencia verificable.</summary>
    public IReadOnlyList<RuleMatch> Analyze(ReadOnlySpan<byte> data, long declaredLength = 0)
    {
        var findings = new Dictionary<string, RuleMatch>(StringComparer.OrdinalIgnoreCase);

        void Add(string id, string name, Severity severity, string evidence)
        {
            if (!findings.TryGetValue(id, out var match))
            {
                match = new RuleMatch { RuleId = id, Name = name, Severity = severity, Category = "pe" };
                findings[id] = match;
            }
            if (!string.IsNullOrWhiteSpace(evidence) && !match.Evidence.Contains(evidence, StringComparer.Ordinal))
                match.Evidence.Add(evidence);
        }

        if (data.Length < 2 || ReadUInt16(data, 0) != DosMagic)
            return [];

        // El tope de cabeceras/tablas PE se aplica aquí, no sólo se declara en
        // AnalysisLimits. El prefijo puede ser mayor (8 MiB) y no debe dar a
        // entender que se recorrieron todas las secciones disponibles.
        if (data.Length > AnalysisLimits.MaxPeBytes)
        {
            var availableBytes = data.Length;
            Add("PE-ANALYSIS-INCOMPLETE", "Análisis PE limitado por el tope de cabeceras", Severity.Info,
                $"prefijo={AnalysisLimits.MaxPeBytes}, disponible={availableBytes}");
            data = data[..AnalysisLimits.MaxPeBytes];
        }

        if (data.Length < 0x40)
        {
            Add("PE-MALFORMED-HEADER", "Cabecera PE incompleta o desplazada", Severity.Low,
                $"bytes={data.Length}");
            return [.. findings.Values];
        }

        var peOffset = ReadInt32(data, 0x3C);
        if (peOffset < 0x40 || peOffset + 24 > data.Length || ReadUInt32(data, peOffset) != PeSignature)
        {
            Add("PE-MALFORMED-HEADER", "Cabecera PE incompleta o desplazada", Severity.Low,
                $"e_lfanew={peOffset}");
            return [.. findings.Values];
        }

        var coff = peOffset + 4;
        var machine = ReadUInt16(data, coff);
        var sectionCount = ReadUInt16(data, coff + 2);
        var optionalSize = ReadUInt16(data, coff + 16);
        var characteristics = ReadUInt16(data, coff + 18);
        var optional = coff + 20;
        if (optional + 2 > data.Length || optionalSize < 96 || optional + optionalSize > data.Length)
        {
            Add("PE-MALFORMED-HEADER", "Cabecera PE incompleta o desplazada", Severity.Low,
                $"optionalSize={optionalSize}, machine=0x{machine:X4}");
            return [.. findings.Values];
        }

        var magic = ReadUInt16(data, optional);
        if (magic is not (Pe32Magic or Pe32PlusMagic))
        {
            Add("PE-MALFORMED-HEADER", "Cabecera PE incompleta o desplazada", Severity.Low,
                $"magic=0x{magic:X4}");
            return [.. findings.Values];
        }

        var isPlus = magic == Pe32PlusMagic;
        var entryRva = ReadUInt32(data, optional + 16);
        var dllCharacteristics = ReadUInt16(data, optional + 70);
        var dataDirectories = optional + (isPlus ? 112 : 96);
        var importRva = optionalSize >= (isPlus ? 120 : 104) && dataDirectories + 12 <= data.Length
            ? ReadUInt32(data, dataDirectories + 8)
            : 0u;

        var sectionsOffset = optional + optionalSize;
        var readableSections = Math.Min(sectionCount, (data.Length - sectionsOffset) / 40);
        if (readableSections < sectionCount)
            Add("PE-ANALYSIS-INCOMPLETE", "Tabla de secciones no completamente disponible", Severity.Info,
                $"declaradas={sectionCount}, disponibles={readableSections}");

        var entrySection = string.Empty;
        var entryExecutable = false;
        long overlayStart = 0;
        var writableExecutable = new List<string>();

        for (var i = 0; i < readableSections; i++)
        {
            var s = sectionsOffset + i * 40;
            var nameBytes = data.Slice(s, 8);
            var name = Encoding.ASCII.GetString(nameBytes).TrimEnd('\0', ' ');
            var virtualSize = ReadUInt32(data, s + 8);
            var virtualAddress = ReadUInt32(data, s + 12);
            var rawSize = ReadUInt32(data, s + 16);
            var rawPointer = ReadUInt32(data, s + 20);
            var sectionFlags = ReadUInt32(data, s + 36);

            if ((sectionFlags & SectionExecute) != 0 && (sectionFlags & SectionWrite) != 0)
                writableExecutable.Add($"{name} (0x{sectionFlags:X8})");

            var span = Math.Max(virtualSize, rawSize);
            if (entryRva >= virtualAddress && span > 0 && entryRva < (long)virtualAddress + span)
            {
                entrySection = name;
                entryExecutable = (sectionFlags & SectionExecute) != 0;
            }

            var end = (long)rawPointer + rawSize;
            if (end > overlayStart && rawSize > 0) overlayStart = end;
        }

        if (writableExecutable.Count > 0)
            Add("PE-WRITABLE-EXECUTABLE-SECTION", "Sección ejecutable y escribible", Severity.Medium,
                string.Join(", ", writableExecutable));

        if (entryRva != 0 && readableSections > 0 && !string.IsNullOrEmpty(entrySection) && !entryExecutable)
            Add("PE-ENTRY-NONEXEC", "Punto de entrada fuera de una sección ejecutable", Severity.Medium,
                $"rva=0x{entryRva:X8}, sección={entrySection}");

        if (sectionCount == 0)
            Add("PE-NO-SECTIONS", "Imagen PE sin secciones declaradas", Severity.Low,
                "NumberOfSections=0");

        if (readableSections > 0 && importRva == 0)
            Add("PE-NO-IMPORTS", "Imagen PE sin tabla de importaciones", Severity.Low,
                "ImportDirectory RVA=0");

        var hardeningMissing = new List<string>();
        if ((dllCharacteristics & DllNxCompatible) == 0) hardeningMissing.Add("DEP");
        if ((dllCharacteristics & DllDynamicBase) == 0) hardeningMissing.Add("ASLR");
        if ((dllCharacteristics & DllGuardCf) == 0) hardeningMissing.Add("CFG");
        if (hardeningMissing.Count >= 2 && (characteristics & 0x2000) == 0)
            Add("PE-MISSING-HARDENING", "Protecciones de cabecera ausentes", Severity.Low,
                string.Join(", ", hardeningMissing));

        if (declaredLength > overlayStart + 1024 * 1024)
            Add("PE-LARGE-OVERLAY", "Datos añadidos después de las secciones", Severity.Low,
                $"overlay={declaredLength - overlayStart} bytes");

        return [.. findings.Values.OrderBy(x => x.RuleId, StringComparer.Ordinal)];
    }

    private static ushort ReadUInt16(ReadOnlySpan<byte> data, int offset) =>
        BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(offset, 2));

    private static int ReadInt32(ReadOnlySpan<byte> data, int offset) =>
        BinaryPrimitives.ReadInt32LittleEndian(data.Slice(offset, 4));

    private static uint ReadUInt32(ReadOnlySpan<byte> data, int offset) =>
        BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset, 4));
}
