using System.Text.Json;
using Aegis.Core;

namespace Aegis.Tests;

public sealed class ScanReportTests
{
    [Fact]
    public void ReportCapsFindingsEvidenceAndContributions()
    {
        var threat = Sample(fileExtension: ".ps1");
        for (var i = 0; i < 20; i++)
        {
            threat.Observation.RuleMatches.Add(new RuleMatch
            {
                RuleId = $"SCRIPT-RULE-{i}",
                Name = new string('N', 300),
                Severity = Severity.Medium,
                Category = "script",
                Evidence = Enumerable.Range(0, 6).Select(j => new string('E', 300 + j)).ToList()
            });
            threat.Decision.Local.Contributions.Add(new ScoreContribution
            {
                Source = "script",
                Reason = new string('R', 300),
                Weight = 22,
                Evidence = new string('D', 300)
            });
        }

        var report = ScanReportBuilder.Build(threat, 12);

        Assert.True(report.Truncated);
        var section = Assert.Single(report.Analyzers, a => a.Category == "script");
        Assert.Equal(ScanReportLimits.MaxFindingsPerAnalyzer, section.Findings.Count);
        Assert.All(section.Findings, f =>
        {
            Assert.Equal(ScanReportLimits.MaxEvidencePerFinding, f.Evidence.Count);
            Assert.True(f.Name.Length <= ScanReportLimits.MaxStringChars + 1);
            Assert.All(f.Evidence, e => Assert.True(e.Length <= ScanReportLimits.MaxStringChars + 1));
        });
        Assert.Equal(ScanReportLimits.MaxContributions, report.Contributions.Count);
        Assert.All(report.Contributions, c => Assert.True(c.Reason.Length <= ScanReportLimits.MaxStringChars + 1));
        var bytes = JsonSerializer.SerializeToUtf8Bytes(report, JsonDefaults.Options);
        Assert.True(bytes.Length <= ScanReportLimits.MaxSerializedBytes);
    }

    [Fact]
    public void NonApplicableAnalyzersAreMarkedAsNotRun()
    {
        var report = ScanReportBuilder.Build(Sample(fileExtension: ".txt"), 3);

        Assert.Contains(report.Analyzers, a => a.Category == "yara" && a.Ran);
        Assert.Contains(report.Analyzers, a => a.Category == "integrity" && a.Ran);
        foreach (var category in new[] { "pe", "script", "archive", "macro" })
        {
            var section = Assert.Single(report.Analyzers, a => a.Category == category);
            Assert.False(section.Ran);
            Assert.False(string.IsNullOrWhiteSpace(section.NotRunReason));
            Assert.Empty(section.Findings);
        }
        Assert.True(report.Coverage.HashReconfirmed);
        Assert.False(report.Truncated);
    }

    [Fact]
    public void IncompleteCoverageIsReportedInsteadOfClean()
    {
        var threat = Sample(fileExtension: ".exe");
        threat.Observation.RuleMatches.AddRange(
        [
            new RuleMatch { RuleId = "ANALYSIS-TRUNCATED", Category = "integrity" },
            new RuleMatch { RuleId = "CONTAINER-INCOMPLETE", Category = "archive" },
            new RuleMatch { RuleId = "ANALYSIS-CONTENT-CHANGED", Category = "integrity" }
        ]);

        var report = ScanReportBuilder.Build(threat, 4);

        Assert.True(report.Coverage.HashTruncated);
        Assert.True(report.Coverage.ContainerTruncated);
        Assert.False(report.Coverage.HashReconfirmed);
        Assert.Equal(3, report.Summary.MatchCount);
    }

    private static ThreatRecord Sample(string fileExtension)
    {
        var threat = new ThreatRecord();
        threat.Observation.Sha256 = new string('a', 64);
        threat.Observation.FileSize = 2048;
        threat.Observation.FileExtension = fileExtension;
        threat.Decision.Local.Score = 42;
        threat.Decision.Local.EvidenceCount = 2;
        return threat;
    }
}
