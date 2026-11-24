using System.Runtime.Versioning;
using System.Text;
using System.Text.RegularExpressions;

namespace Aegis.Core;

/// <summary>
/// Analizador determinista de scripts (PowerShell, CMD/BAT, JS, VBS, HTA).
/// No ejecuta nada: decodifica Base64 observable y correlaciona señales
/// independientes. Una sola cadena sospechosa no basta para bloquear.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ScriptInspector
{
    private static readonly Regex Base64Token = new(
        @"[A-Za-z0-9+/]{40,}={0,2}", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly string[] EncodedTokens =
        ["-enc ", "-encodedcommand", "-e jab", "frombase64string", "certutil -decode"];

    private static readonly string[] ExpressionTokens =
        ["iex(", "iex ", "invoke-expression", "invoke-item", "invoke-command"];

    private static readonly string[] ExecutionTokens =
        ["wscript.shell", "createobject(", "shell.application", "mshta ", "rundll32 ", "regsvr32 ", "cscript //b"];

    private static readonly string[] DownloadTokens =
        ["urldownloadtofile", "downloadstring", "downloadfile", "iwr ", "wget ", "curl "];

    public IReadOnlyList<RuleMatch> Analyze(ReadOnlySpan<byte> data, string extension)
    {
        var ext = extension.TrimStart('.').ToLowerInvariant();
        if (ext is not ("ps1" or "psm1" or "bat" or "cmd" or "js" or "jse" or "vbs" or "hta"))
            return [];

        var max = Math.Min(data.Length, AnalysisLimits.MaxScriptBytes);
        var text = Decode(data[..max]);
        var lower = text.ToLowerInvariant();
        var signals = new List<string>();

        if (ContainsAny(lower, EncodedTokens)) signals.Add("codificación Base64/PowerShell");
        if (ContainsAny(lower, ExpressionTokens)) signals.Add("evaluación dinámica");
        if (ContainsAny(lower, ExecutionTokens)) signals.Add("ejecución externa");
        if (ContainsAny(lower, DownloadTokens)) signals.Add("descarga");
        if (Count(lower, '`') >= 3 || Regex.IsMatch(text, @"['""]\s*\+\s*['""]") ||
            Regex.IsMatch(text, @"\[char\]\d"))
            signals.Add("ofuscación por concatenación/escapes");

        var results = new List<RuleMatch>();
        var longestLine = text.Split('\n').Select(x => x.TrimEnd('\r').Length).DefaultIfEmpty(0).Max();
        if (longestLine > 8192 && !signals.Contains("ofuscación por concatenación/escapes"))
            signals.Add("línea extremadamente larga");

        foreach (Match match in Base64Token.Matches(text))
        {
            try
            {
                var decoded = Convert.FromBase64String(match.Value);
                if (FileInspector.ContainsEicarSample(decoded))
                {
                    results.Add(new RuleMatch
                    {
                        RuleId = "EICAR-STANDARD-TEST",
                        Name = "Fichero de prueba EICAR codificado en Base64",
                        Severity = Severity.Critical,
                        Category = "script",
                        Evidence = [$"Base64 decodificado ({decoded.Length} bytes)"]
                    });
                    continue;
                }
                var decodedLower = Encoding.UTF8.GetString(decoded.AsSpan(0, Math.Min(decoded.Length, 64 * 1024)))
                    .ToLowerInvariant();
                if (ContainsAny(decodedLower, ExpressionTokens) || ContainsAny(decodedLower, ExecutionTokens))
                    signals.Add("carga útil Base64 con ejecución");
            }
            catch (FormatException)
            {
                // Un token parecido a Base64 no es evidencia por sí solo.
            }
        }

        var distinct = signals.Distinct(StringComparer.Ordinal).Take(8).ToList();
        if (distinct.Count == 0) return results;

        var severity = distinct.Count switch
        {
            >= 3 => Severity.High,
            2 => Severity.Medium,
            _ => Severity.Info
        };
        var id = distinct.Count switch
        {
            >= 3 => "SCRIPT-MULTIPLE-EXECUTION-SIGNALS",
            2 => "SCRIPT-SUSPICIOUS-COMBINATION",
            _ => "SCRIPT-SINGLE-SIGNAL"
        };
        results.Add(new RuleMatch
        {
            RuleId = id,
            Name = "Señales de script sospechoso",
            Severity = severity,
            Category = "script",
            Evidence = distinct
        });
        return results.OrderBy(x => x.RuleId, StringComparer.Ordinal).ToList();
    }

    private static string Decode(ReadOnlySpan<byte> data)
    {
        if (data.Length >= 2 && data[0] == 0xFF && data[1] == 0xFE)
            return Encoding.Unicode.GetString(data[2..]);
        if (data.Length >= 2 && data[0] == 0xFE && data[1] == 0xFF)
            return Encoding.BigEndianUnicode.GetString(data[2..]);
        // Muchos scripts no llevan BOM. Detectar el patrón de bytes nulos evita
        // perder señales por decodificar UTF-16 como UTF-8.
        if (data.Length >= 4 && data[1] == 0 && data[3] == 0 && data[0] != 0 && data[2] != 0)
            return Encoding.Unicode.GetString(data);
        if (data.Length >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF)
            return Encoding.UTF8.GetString(data[3..]);
        return Encoding.UTF8.GetString(data);
    }

    private static bool ContainsAny(string text, string[] tokens)
    {
        foreach (var token in tokens)
            if (text.Contains(token, StringComparison.Ordinal)) return true;
        return false;
    }

    private static int Count(string text, char value)
    {
        var count = 0;
        foreach (var c in text) if (c == value) count++;
        return count;
    }
}
