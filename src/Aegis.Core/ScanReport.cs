using System.Text.Json;

namespace Aegis.Core;

/// <summary>
/// Topes del informe manual. Están por debajo del límite de 256 KiB de la
/// respuesta IPC: el informe es una proyección acotada de evidencia ya
/// calculada, nunca una copia del fichero ni un segundo análisis.
/// </summary>
public static class ScanReportLimits
{
    public const int MaxFindingsPerAnalyzer = 16;
    public const int MaxEvidencePerFinding = 4;
    public const int MaxContributions = 12;
    public const int MaxStringChars = 160;
    public const int MaxSerializedBytes = 192 * 1024;
}

/// <summary>
/// Informe local y determinista de un análisis manual. No añade detecciones:
/// reordena y acota las evidencias que el motor ya produjo.
/// </summary>
public sealed class ScanReport
{
    public string SchemaVersion { get; set; } = "1.0";
    public long ElapsedMs { get; set; }
    public bool Truncated { get; set; }
    public ScanCoverage Coverage { get; set; } = new();
    public List<AnalyzerSection> Analyzers { get; set; } = [];
    public List<ScoreContribution> Contributions { get; set; } = [];
    public ScanSummary Summary { get; set; } = new();
}

public sealed class ScanCoverage
{
    public long BytesInspected { get; set; }
    public long MaxScanBytes { get; set; } = AnalysisLimits.MaxScanBytes;
    public bool HashTruncated { get; set; }
    public bool ContainerTruncated { get; set; }
    public bool HashReconfirmed { get; set; }
}

public sealed class AnalyzerSection
{
    public string Category { get; set; } = string.Empty;
    public bool Ran { get; set; }
    public string NotRunReason { get; set; } = string.Empty;
    public List<RuleMatch> Findings { get; set; } = [];
}

public sealed class ScanSummary
{
    public int MatchCount { get; set; }
    public int EvidenceCount { get; set; }
    public int VerifiedIndicatorCount { get; set; }
    public int CriticalIndicatorCount { get; set; }
    public double Score { get; set; }
}

/// <summary>
/// Construye el informe a partir del <see cref="ThreatRecord"/> resultante.
/// No abre ficheros, no consulta estado persistente y no modifica la decisión.
/// </summary>
public static class ScanReportBuilder
{
    private static readonly string[] Categories = ["yara", "pe", "script", "archive", "macro", "integrity"];

    private static readonly HashSet<string> PeExtensions = new(StringComparer.OrdinalIgnoreCase)
        { ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".drv" };

    private static readonly HashSet<string> ScriptExtensions = new(StringComparer.OrdinalIgnoreCase)
        { ".ps1", ".psm1", ".bat", ".cmd", ".js", ".jse", ".vbs", ".hta" };

    private static readonly HashSet<string> ArchiveExtensions = new(StringComparer.OrdinalIgnoreCase)
        { ".zip", ".jar", ".gz", ".tgz", ".tar" };

    private static readonly HashSet<string> MacroExtensions = new(StringComparer.OrdinalIgnoreCase)
        { ".doc", ".xls", ".ppt", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm" };

    public static ScanReport Build(ThreatRecord threat, long elapsedMs)
    {
        ArgumentNullException.ThrowIfNull(threat);
        var observation = threat.Observation;
        var matches = observation.RuleMatches;
        var truncated = false;

        var hasChanged = HasRule(matches, "ANALYSIS-CONTENT-CHANGED");
        var report = new ScanReport
        {
            ElapsedMs = Math.Max(0, elapsedMs),
            Coverage = new ScanCoverage
            {
                BytesInspected = Math.Min(Math.Max(observation.FileSize, 0), AnalysisLimits.MaxScanBytes),
                HashTruncated = HasRule(matches, "ANALYSIS-TRUNCATED"),
                ContainerTruncated = HasRule(matches, "CONTAINER-INCOMPLETE"),
                HashReconfirmed = !string.IsNullOrWhiteSpace(observation.Sha256) && !hasChanged
            },
            Summary = new ScanSummary
            {
                MatchCount = matches.Select(m => m.RuleId).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
                EvidenceCount = threat.Decision.Local.EvidenceCount,
                VerifiedIndicatorCount = threat.Decision.Local.HasVerifiedIndicator ? 1 : 0,
                CriticalIndicatorCount = threat.Decision.Local.HasCriticalIndicator ? 1 : 0,
                Score = threat.Decision.Local.Score
            }
        };

        foreach (var category in Categories)
        {
            var section = new AnalyzerSection
            {
                Category = category,
                Ran = AnalyzerRan(category, observation, matches)
            };
            if (!section.Ran) section.NotRunReason = NotRunReason(category, observation);

            var relevant = matches.Where(m =>
                string.Equals(m.Category, category, StringComparison.OrdinalIgnoreCase)).ToList();
            if (relevant.Count > ScanReportLimits.MaxFindingsPerAnalyzer) truncated = true;
            foreach (var match in relevant.Take(ScanReportLimits.MaxFindingsPerAnalyzer))
            {
                if (match.Evidence.Count > ScanReportLimits.MaxEvidencePerFinding) truncated = true;
                section.Findings.Add(new RuleMatch
                {
                    RuleId = Clip(match.RuleId, ScanReportLimits.MaxStringChars),
                    Name = Clip(match.Name, ScanReportLimits.MaxStringChars),
                    Severity = match.Severity,
                    Category = category,
                    Evidence = match.Evidence
                        .Take(ScanReportLimits.MaxEvidencePerFinding)
                        .Select(e => Clip(e, ScanReportLimits.MaxStringChars))
                        .ToList()
                });
            }
            report.Analyzers.Add(section);
        }

        var contributions = threat.Decision.Local.Contributions;
        if (contributions.Count > ScanReportLimits.MaxContributions) truncated = true;
        foreach (var contribution in contributions.Take(ScanReportLimits.MaxContributions))
        {
            report.Contributions.Add(new ScoreContribution
            {
                Source = Clip(contribution.Source, ScanReportLimits.MaxStringChars),
                Reason = Clip(contribution.Reason, ScanReportLimits.MaxStringChars),
                Weight = contribution.Weight,
                Evidence = Clip(contribution.Evidence, ScanReportLimits.MaxStringChars)
            });
        }

        // Defensa en profundidad: si una combinación improbable de reglas
        // acercara la respuesta al límite del pipe, se degrada el informe en
        // lugar de convertir la operación en un error para la interfaz.
        if (JsonSerializer.SerializeToUtf8Bytes(report, JsonDefaults.Options).Length > ScanReportLimits.MaxSerializedBytes)
        {
            truncated = true;
            foreach (var section in report.Analyzers)
            {
                foreach (var finding in section.Findings)
                {
                    finding.Name = Clip(finding.Name, 60);
                    finding.Evidence.Clear();
                }
            }
            foreach (var contribution in report.Contributions)
            {
                contribution.Reason = Clip(contribution.Reason, 60);
                contribution.Evidence = string.Empty;
            }
        }

        report.Truncated = truncated;
        return report;
    }

    private static bool HasRule(IEnumerable<RuleMatch> matches, string ruleId) =>
        matches.Any(m => string.Equals(m.RuleId, ruleId, StringComparison.OrdinalIgnoreCase));

    private static bool AnalyzerRan(string category, Observation observation, IReadOnlyList<RuleMatch> matches)
    {
        if (string.IsNullOrWhiteSpace(observation.Sha256)) return false;
        if (matches.Any(m => string.Equals(m.Category, category, StringComparison.OrdinalIgnoreCase))) return true;
        var extension = observation.FileExtension ?? string.Empty;
        return category switch
        {
            "yara" or "integrity" => true,
            "pe" => PeExtensions.Contains(extension),
            "script" => ScriptExtensions.Contains(extension),
            "archive" => ArchiveExtensions.Contains(extension),
            "macro" => MacroExtensions.Contains(extension),
            _ => false
        };
    }

    private static string NotRunReason(string category, Observation observation) =>
        string.IsNullOrWhiteSpace(observation.Sha256)
            ? "inspección de fichero no disponible"
            : "extensión no aplicable para " + category;

    private static string Clip(string value, int max)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;
        return value.Length <= max ? value : value[..max] + "…";
    }
}
