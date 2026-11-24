using System.IO.Compression;
using System.Runtime.Versioning;
using System.Text;

namespace Aegis.Core;

/// <summary>
/// Analiza ZIP/JAR, GZIP y TAR en memoria, con topes declarados antes de
/// descomprimir. No extrae ficheros a disco: las rutas internas solo se usan
/// como evidencia. Un archivo cifrado o dañado se marca como no verificado,
/// nunca como malware.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ArchiveInspector
{
    private static readonly byte[] ZipMagic = [0x50, 0x4B, 0x03, 0x04];
    private static readonly byte[] GzipMagic = [0x1F, 0x8B];

    public async Task<IReadOnlyList<RuleMatch>> AnalyzeAsync(
        byte[] bytes,
        string extension,
        CancellationToken ct = default)
    {
        var context = new Context(ct);
        var ext = NormalizeExtension(extension);
        switch (ext)
        {
            case ".zip":
            case ".jar":
                await AnalyzeZipAsync(bytes, 0, context).ConfigureAwait(false);
                break;
            case ".gz":
            case ".tgz":
                await AnalyzeGzipAsync(bytes, 0, context).ConfigureAwait(false);
                break;
            case ".tar":
                await AnalyzeTarAsync(bytes, 0, context).ConfigureAwait(false);
                break;
        }
        return context.Results();
    }

    private static string NormalizeExtension(string extension)
    {
        if (string.IsNullOrWhiteSpace(extension)) return string.Empty;
        var value = extension.Trim();
        if (!value.StartsWith('.')) value = "." + value;
        return value.ToLowerInvariant();
    }

    private async Task AnalyzeZipAsync(byte[] bytes, int depth, Context context)
    {
        context.CancellationToken.ThrowIfCancellationRequested();
        try
        {
            using var source = new MemoryStream(bytes, writable: false);
            using var zip = new ZipArchive(source, ZipArchiveMode.Read);
            if (zip.Entries.Count > AnalysisLimits.MaxArchiveEntries)
                context.Add("ARCHIVE-TOO-MANY-ENTRIES", "Demasiadas entradas en el archivo", Severity.Medium,
                    $"entradas={zip.Entries.Count}, límite={AnalysisLimits.MaxArchiveEntries}");

            foreach (var entry in zip.Entries)
            {
                context.CancellationToken.ThrowIfCancellationRequested();
                context.Entries++;
                var name = Sanitize(entry.FullName);
                if (name.EndsWith('/')) continue;

                if (entry.Length > AnalysisLimits.MaxArchiveMemberBytes)
                {
                    context.Add("ARCHIVE-BOMB", "Miembro declarado por encima del límite", Severity.High,
                        $"{name}: {entry.Length} bytes");
                    continue;
                }
                context.Total += entry.Length;
                if (context.Total > AnalysisLimits.MaxArchiveTotalBytes)
                {
                    context.Add("ARCHIVE-BOMB", "Total descomprimido por encima del límite", Severity.High,
                        $"{name}: acumulado={context.Total} bytes");
                    break;
                }
                if (entry.CompressedLength > 0 && entry.Length > 1024 * 1024 &&
                    entry.Length / entry.CompressedLength > 50)
                {
                    context.Add("ARCHIVE-HIGH-RATIO", "Ratio de compresión anómalo", Severity.Low,
                        $"{name}: {entry.Length / entry.CompressedLength}:1");
                }

                try
                {
                    using var member = entry.Open();
                    var (data, truncated) = await ReadCappedAsync(member,
                        AnalysisLimits.MaxArchiveMemberBytes, context.CancellationToken).ConfigureAwait(false);
                    if (truncated)
                        context.Add("ARCHIVE-BOMB", "Miembro truncado por límite antibomba", Severity.High, name);
                    await AnalyzeMemberAsync(data, name, depth, context).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is InvalidDataException or IOException)
                {
                    context.Add("ARCHIVE-UNVERIFIED", "Miembro cifrado o ilegible", Severity.Info, name);
                }
            }
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException)
        {
            context.Add("ARCHIVE-CORRUPT", "Archivo dañado o no compatible", Severity.Info, ex.Message);
        }
    }

    private async Task AnalyzeGzipAsync(byte[] bytes, int depth, Context context)
    {
        context.CancellationToken.ThrowIfCancellationRequested();
        try
        {
            using var source = new MemoryStream(bytes, writable: false);
            using var gzip = new GZipStream(source, CompressionMode.Decompress);
            var (data, truncated) = await ReadCappedAsync(gzip,
                AnalysisLimits.MaxArchiveTotalBytes, context.CancellationToken).ConfigureAwait(false);
            if (truncated)
                context.Add("ARCHIVE-BOMB", "GZIP truncado por límite antibomba", Severity.High,
                    $"{data.Length} bytes leídos");

            if (IsTar(data))
                await AnalyzeTarAsync(data, depth, context).ConfigureAwait(false);
            else
                await AnalyzeMemberAsync(data, "gzip:stream", depth, context).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException)
        {
            context.Add("ARCHIVE-CORRUPT", "GZIP dañado o incompatible", Severity.Info, ex.Message);
        }
    }

    private async Task AnalyzeTarAsync(byte[] bytes, int depth, Context context)
    {
        context.CancellationToken.ThrowIfCancellationRequested();
        var offset = 0;
        while (offset + 512 <= bytes.Length)
        {
            var header = bytes.AsSpan(offset, 512);
            if (header.IndexOfAnyExcept((byte)0) < 0) break; // dos bloques de fin

            var name = ReadAsciiZ(header.Slice(0, 100));
            var prefix = ReadAsciiZ(header.Slice(345, 155));
            var fullName = Sanitize(string.IsNullOrEmpty(prefix) ? name : prefix + "/" + name);
            var size = ParseOctal(header.Slice(124, 12));
            if (size < 0)
            {
                context.Add("ARCHIVE-CORRUPT", "Entrada TAR con tamaño inválido", Severity.Info, fullName);
                break;
            }
            if (size > AnalysisLimits.MaxArchiveMemberBytes)
            {
                context.Add("ARCHIVE-BOMB", "Miembro TAR por encima del límite", Severity.High,
                    $"{fullName}: {size} bytes");
                break;
            }
            context.Entries++;
            context.Total += size;
            if (context.Total > AnalysisLimits.MaxArchiveTotalBytes)
            {
                context.Add("ARCHIVE-BOMB", "Total TAR por encima del límite", Severity.High, fullName);
                break;
            }

            var available = Math.Min(size, bytes.Length - offset - 512);
            if (available > 0)
                await AnalyzeMemberAsync(bytes.AsSpan(offset + 512, (int)available).ToArray(), fullName, depth, context)
                    .ConfigureAwait(false);
            offset += 512 + (int)((size + 511) / 512) * 512;
        }
    }

    private async Task AnalyzeMemberAsync(byte[] data, string name, int depth, Context context)
    {
        if (FileInspector.ContainsEicarSample(data))
            context.Add("EICAR-STANDARD-TEST", "Fichero de prueba EICAR dentro del archivo", Severity.Critical,
                name);

        var ext = NormalizeExtension(Path.GetExtension(name));
        if (ext is ".exe" or ".dll" or ".sys" or ".scr" or ".com" or ".cpl" or ".ocx" or ".drv" or
            ".msi" or ".msp" or ".ps1" or ".bat" or ".cmd" or ".vbs" or ".js" or ".jse" or ".hta")
            context.Add("ARCHIVE-EXECUTABLE-MEMBER", "Miembro ejecutable o script dentro del archivo", Severity.Medium,
                name);

        if (depth >= AnalysisLimits.MaxArchiveDepth) return;

        if (data.StartsWith(ZipMagic))
        {
            context.Add("ARCHIVE-NESTED", "Archivo anidado detectado", Severity.Low,
                $"{name}, profundidad={depth + 1}");
            await AnalyzeZipAsync(data, depth + 1, context).ConfigureAwait(false);
        }
        else if (data.StartsWith(GzipMagic))
        {
            context.Add("ARCHIVE-NESTED", "Archivo anidado detectado", Severity.Low,
                $"{name}, profundidad={depth + 1}");
            await AnalyzeGzipAsync(data, depth + 1, context).ConfigureAwait(false);
        }
        else if (IsTar(data))
        {
            context.Add("ARCHIVE-NESTED", "Archivo anidado detectado", Severity.Low,
                $"{name}, profundidad={depth + 1}");
            await AnalyzeTarAsync(data, depth + 1, context).ConfigureAwait(false);
        }
    }

    private static async Task<(byte[] data, bool truncated)> ReadCappedAsync(
        Stream stream, long maxBytes, CancellationToken ct)
    {
        using var output = new MemoryStream();
        var buffer = new byte[64 * 1024];
        var remaining = maxBytes;
        var truncated = false;
        while (remaining > 0)
        {
            var wanted = (int)Math.Min(buffer.Length, remaining);
            var read = await stream.ReadAsync(buffer.AsMemory(0, wanted), ct).ConfigureAwait(false);
            if (read <= 0) break;
            output.Write(buffer, 0, read);
            remaining -= read;
            if (output.Length >= maxBytes)
            {
                var extra = await stream.ReadAsync(buffer.AsMemory(0, 1), ct).ConfigureAwait(false);
                truncated = extra > 0;
                break;
            }
        }
        return (output.ToArray(), truncated);
    }

    private static bool IsTar(ReadOnlySpan<byte> data) =>
        data.Length >= 512 && data.Slice(257, 5).SequenceEqual("ustar"u8);

    private static long ParseOctal(ReadOnlySpan<byte> value)
    {
        var text = ReadAsciiZ(value).Trim().Trim('\0');
        if (string.IsNullOrEmpty(text)) return 0;
        try { return Convert.ToInt64(text, 8); }
        catch (FormatException) { return -1; }
        catch (OverflowException) { return -1; }
    }

    private static string ReadAsciiZ(ReadOnlySpan<byte> value)
    {
        var end = value.IndexOf((byte)0);
        var slice = end >= 0 ? value[..end] : value;
        return Encoding.ASCII.GetString(slice);
    }

    private static string Sanitize(string value)
    {
        var clean = value.Replace('\r', ' ').Replace('\n', ' ').Trim();
        return clean.Length <= 200 ? clean : clean[..200] + "…";
    }

    private sealed class Context(CancellationToken cancellationToken)
    {
        private readonly Dictionary<string, RuleMatch> _findings = new(StringComparer.OrdinalIgnoreCase);

        public CancellationToken CancellationToken { get; } = cancellationToken;
        public int Entries { get; set; }
        public long Total { get; set; }

        public void Add(string id, string name, Severity severity, string evidence)
        {
            if (!_findings.TryGetValue(id, out var match))
            {
                match = new RuleMatch { RuleId = id, Name = name, Severity = severity, Category = "archive" };
                _findings[id] = match;
            }
            if (!string.IsNullOrWhiteSpace(evidence) && !match.Evidence.Contains(evidence, StringComparer.Ordinal))
                match.Evidence.Add(evidence);
        }

        public IReadOnlyList<RuleMatch> Results() =>
            [.. _findings.Values.OrderBy(x => x.RuleId, StringComparer.Ordinal)];
    }
}
