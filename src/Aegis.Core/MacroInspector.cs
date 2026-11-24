using System.Buffers.Binary;
using System.Globalization;
using System.IO.Compression;
using System.Text;

namespace Aegis.Core;

/// <summary>
/// Detecta proyectos VBA en documentos OOXML (ZIP) y en contenedores OLE/CFB
/// antiguos. Solo lee bytes: no ejecuta macros, no extrae a disco y no abre
/// aplicación de Office. Un contenedor cifrado se marca como no verificado.
/// </summary>
public sealed class MacroInspector
{
    private static readonly byte[] OleSignature = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

    private static readonly string[] AutoRunTokens =
        ["auto_open", "document_open", "workbook_open", "autoexec", "autoexit"];

    private static readonly string[] ExecutionTokens =
        ["shell(", "createobject", "wscript.shell", "urldownloadtofile", "application.run", "kill "];

    public async Task<IReadOnlyList<RuleMatch>> AnalyzeAsync(
        byte[] bytes,
        string extension,
        CancellationToken ct = default)
    {
        var context = new Context();
        var ext = NormalizeExtension(extension);
        var ooxml = ext is ".docx" or ".xlsx" or ".pptx" or ".docm" or ".xlsm" or ".pptm";
        var legacy = ext is ".doc" or ".xls" or ".ppt";

        if (!ooxml && !legacy) return context.Results();

        if (ooxml)
        {
            try
            {
                using var source = new MemoryStream(bytes, writable: false);
                using var zip = new ZipArchive(source, ZipArchiveMode.Read);
                var projects = zip.Entries
                    .Where(e => e.FullName.EndsWith("vbaProject.bin", StringComparison.OrdinalIgnoreCase))
                    .Take(16)
                    .ToList();
                if (projects.Count == 0) return context.Results();

                foreach (var entry in projects)
                {
                    ct.ThrowIfCancellationRequested();
                    if (entry.Length > AnalysisLimits.MaxMacroStreamBytes)
                    {
                        context.Add("MACRO-UNVERIFIED", "Proyecto VBA demasiado grande para analizar", Severity.Info,
                            Sanitize(entry.FullName));
                        continue;
                    }
                    using var stream = entry.Open();
                    var data = await ReadAllAsync(stream, (int)Math.Min(entry.Length, AnalysisLimits.MaxMacroStreamBytes), ct)
                        .ConfigureAwait(false);
                    context.Add("MACRO-PROJECT-PRESENT", "Proyecto VBA incrustado en el documento", Severity.Medium,
                        Sanitize(entry.FullName));
                    context.AnalyzeVbaBytes(data, "OOXML:" + Sanitize(entry.FullName));
                }
            }
            catch (Exception ex) when (ex is InvalidDataException or IOException)
            {
                context.Add("MACRO-UNVERIFIED", "Contenedor OOXML cifrado o ilegible", Severity.Info, ex.Message);
            }
            return context.Results();
        }

        if (!bytes.AsSpan().StartsWith(OleSignature))
            return context.Results();

        var streams = ReadCfbVbaStreams(bytes, context);
        if (streams.Count == 0)
            context.Add("MACRO-UNVERIFIED", "Contenedor OLE sin streams VBA legibles", Severity.Info, "CFB");
        foreach (var stream in streams)
        {
            context.Add("MACRO-PROJECT-PRESENT", "Proyecto VBA incrustado en el documento", Severity.Medium,
                Sanitize(stream.Name));
            context.AnalyzeVbaBytes(stream.Data, "OLE:" + Sanitize(stream.Name));
        }
        return context.Results();
    }

    private static List<(string Name, byte[] Data)> ReadCfbVbaStreams(byte[] bytes, Context context)
    {
        var result = new List<(string, byte[])>();
        if (bytes.Length < 512) return result;

        var sectorShift = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(30, 2));
        var sectorSize = 1 << sectorShift;
        if (sectorSize is not (512 or 4096) || bytes.Length < sectorSize) return result;

        var fatCount = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(44, 4));
        var firstDirectory = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(48, 4));
        var miniCutoff = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(56, 4));
        var maxSectors = bytes.Length / sectorSize;
        if (fatCount <= 0 || fatCount > 4096 || firstDirectory < 0 || firstDirectory >= maxSectors)
            return result;

        var fat = new List<int>();
        for (var i = 0; i < 109 && fat.Count < fatCount * (sectorSize / 4); i++)
        {
            var sector = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(76 + i * 4, 4));
            if (sector < 0 || sector >= maxSectors) continue;
            var offset = (sector + 1) * sectorSize;
            for (var j = 0; j < sectorSize / 4; j++)
                fat.Add(BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(offset + j * 4, 4)));
        }

        var visited = new HashSet<int>();
        var directory = firstDirectory;
        var entries = 0;
        while (directory >= 0 && directory < maxSectors && entries < 4096 && visited.Add(directory))
        {
            var offset = (directory + 1) * sectorSize;
            for (var i = 0; i < sectorSize / 128; i++)
            {
                var entry = bytes.AsSpan(offset + i * 128, 128);
                var nameLength = BinaryPrimitives.ReadUInt16LittleEndian(entry.Slice(64, 2));
                var type = entry[66];
                if (type != 2 || nameLength < 2 || nameLength > 64) continue;

                var name = Encoding.Unicode.GetString(entry.Slice(0, Math.Min(nameLength - 2, 64)));
                if (!name.Contains("VBA", StringComparison.OrdinalIgnoreCase) &&
                    !name.Contains("Project", StringComparison.OrdinalIgnoreCase) &&
                    !name.Equals("dir", StringComparison.OrdinalIgnoreCase))
                    continue;

                var start = BinaryPrimitives.ReadInt32LittleEndian(entry.Slice(116, 4));
                var size = BinaryPrimitives.ReadInt64LittleEndian(entry.Slice(120, 8));
                if (size <= 0 || size > AnalysisLimits.MaxMacroStreamBytes) continue;
                if (size < miniCutoff)
                {
                    context.Add("MACRO-UNVERIFIED", "Stream VBA en mini-FAT no analizado", Severity.Info,
                        Sanitize(name));
                    continue;
                }

                var data = ReadFatChain(bytes, fat, start, (int)Math.Min(size, AnalysisLimits.MaxMacroStreamBytes),
                    sectorSize, maxSectors);
                if (data.Length > 0) result.Add((name, data));
            }
            if (directory >= fat.Count) break;
            directory = fat[directory];
            entries++;
        }
        return result;
    }

    private static byte[] ReadFatChain(byte[] bytes, List<int> fat, int start, int size, int sectorSize, int maxSectors)
    {
        using var output = new MemoryStream();
        var visited = new HashSet<int>();
        var sector = start;
        while (sector >= 0 && sector < maxSectors && output.Length < size && visited.Add(sector))
        {
            var offset = (sector + 1) * sectorSize;
            if (offset + sectorSize > bytes.Length) break;
            var take = Math.Min(sectorSize, size - (int)output.Length);
            output.Write(bytes, offset, take);
            if (sector >= fat.Count) break;
            sector = fat[sector];
        }
        return output.ToArray();
    }

    private static async Task<byte[]> ReadAllAsync(Stream stream, int maxBytes, CancellationToken ct)
    {
        using var output = new MemoryStream();
        var buffer = new byte[64 * 1024];
        while (output.Length < maxBytes)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, maxBytes - output.Length)), ct)
                .ConfigureAwait(false);
            if (read <= 0) break;
            output.Write(buffer, 0, read);
        }
        return output.ToArray();
    }

    private static string NormalizeExtension(string extension)
    {
        if (string.IsNullOrWhiteSpace(extension)) return string.Empty;
        var value = extension.Trim();
        if (!value.StartsWith('.')) value = "." + value;
        return value.ToLowerInvariant();
    }

    private static string Sanitize(string value)
    {
        var clean = value.Replace('\r', ' ').Replace('\n', ' ').Trim();
        return clean.Length <= 160 ? clean : clean[..160] + "…";
    }

    private sealed class Context
    {
        private readonly Dictionary<string, RuleMatch> _findings = new(StringComparer.OrdinalIgnoreCase);

        public void Add(string id, string name, Severity severity, string evidence)
        {
            if (!_findings.TryGetValue(id, out var match))
            {
                match = new RuleMatch { RuleId = id, Name = name, Severity = severity, Category = "macro" };
                _findings[id] = match;
            }
            if (!string.IsNullOrWhiteSpace(evidence) && !match.Evidence.Contains(evidence, StringComparer.Ordinal))
                match.Evidence.Add(evidence);
        }

        public void AnalyzeVbaBytes(byte[] data, string name)
        {
            var text = Encoding.UTF8.GetString(data.AsSpan(0, Math.Min(data.Length, 2 * 1024 * 1024)))
                .ToLowerInvariant();
            var auto = AutoRunTokens.Any(t => text.Contains(t, StringComparison.Ordinal));
            var execution = ExecutionTokens.Any(t => text.Contains(t, StringComparison.Ordinal));
            if (auto && execution)
                Add("MACRO-AUTORUN-EXECUTION", "Macro con autoarranque y ejecución externa", Severity.High, name);
            else if (auto)
                Add("MACRO-AUTORUN", "Macro con disparador automático", Severity.Low, name);
        }

        public IReadOnlyList<RuleMatch> Results() =>
            [.. _findings.Values.OrderBy(x => x.RuleId, StringComparer.Ordinal)];
    }
}
