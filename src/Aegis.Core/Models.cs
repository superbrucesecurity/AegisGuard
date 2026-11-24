using System.Text.Json;
using System.Text.Json.Serialization;

namespace Aegis.Core;

public enum EventKind
{
    FileCreated,
    FileModified,
    ProcessStarted,
    NetworkConnection,
    DnsQuery,
    RegistryChanged,
    ServiceChanged,
    PersistenceChanged,
    ManualScan
}

public enum Severity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

public enum Verdict
{
    Allow,
    Monitor,
    Block,
    Quarantine
}

public enum SignatureStatus
{
    Unknown,
    SignedTrusted,
    SignedUntrusted,
    Unsigned,
    NotApplicable
}

public sealed class Observation
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;
    public EventKind Kind { get; set; }
    public string Subject { get; set; } = string.Empty;
    public string? ProcessId { get; set; }
    public string? ParentProcess { get; set; }
    public string? RemoteAddress { get; set; }
    public string? RemotePort { get; set; }
    public string? LocalPort { get; set; }
    public string? Protocol { get; set; }
    public string? Sha256 { get; set; }
    public long FileSize { get; set; }
    public string? FileExtension { get; set; }
    public SignatureStatus Signature { get; set; } = SignatureStatus.Unknown;
    public double Reputation { get; set; } = 0.5;
    public List<string> BehaviorFlags { get; set; } = [];
    public List<RuleMatch> RuleMatches { get; set; } = [];
    public string Source { get; set; } = "local";
    public Dictionary<string, string> Metadata { get; set; } = [];
}

public sealed class RuleMatch
{
    public string RuleId { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public Severity Severity { get; set; }
    public List<string> Evidence { get; set; } = [];
}

public sealed class LocalAssessment
{
    public double Score { get; set; }
    public int EvidenceCount { get; set; }
    public List<ScoreContribution> Contributions { get; set; } = [];
    public bool HasCriticalIndicator { get; set; }
}

public sealed class ScoreContribution
{
    public string Source { get; set; } = string.Empty;
    public string Reason { get; set; } = string.Empty;
    public double Weight { get; set; }
}

public sealed class AiClassification
{
    public string Model { get; set; } = "none";
    public string ChoiceLabel { get; set; } = "INDETERMINATE";
    public double Clean { get; set; }
    public double Suspicious { get; set; }
    public double Malicious { get; set; }
    public double Confidence { get; set; }
    public double SeverityScore { get; set; }
    public bool IsValid { get; set; }
    public string? Error { get; set; }
    public long LatencyMs { get; set; }
    public string RequestId { get; set; } = string.Empty;
}

public sealed class DecisionResult
{
    public string ObservationId { get; set; } = string.Empty;
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;
    public Verdict Verdict { get; set; }
    public Severity Severity { get; set; }
    public double Risk { get; set; }
    public double Confidence { get; set; }
    public LocalAssessment Local { get; set; } = new();
    public AiClassification Ai { get; set; } = new();
    public List<string> Reasons { get; set; } = [];
    public bool AiWasDecisive { get; set; }
}

public sealed class ThreatRecord
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;
    public Observation Observation { get; set; } = new();
    public DecisionResult Decision { get; set; } = new();
    public bool Remediated { get; set; }
    public string? RemediationDetail { get; set; }
}

public sealed class QuarantineItem
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;
    public string OriginalPath { get; set; } = string.Empty;
    public string Sha256 { get; set; } = string.Empty;
    public long Length { get; set; }
    public string Reason { get; set; } = string.Empty;
    public string PayloadFile { get; set; } = string.Empty;
    public string ThreatId { get; set; } = string.Empty;
    public bool Restored { get; set; }
}

public sealed class FirewallRuleSpec
{
    public string Name { get; set; } = string.Empty;
    public bool Block { get; set; } = true;
    public bool Inbound { get; set; }
    public string? ApplicationPath { get; set; }
    public string? RemoteAddresses { get; set; }
    public int Protocol { get; set; } = 256;
    public int? RemotePort { get; set; }
    public string Description { get; set; } = string.Empty;
}

public sealed class PolicySettings
{
    public bool AiEnabled { get; set; } = true;
    public bool LearningMode { get; set; } = true;
    public bool AutoQuarantine { get; set; } = true;
    public bool AutoBlockNetwork { get; set; } = true;
    public double MonitorThreshold { get; set; } = 25;
    public double BlockThreshold { get; set; } = 58;
    public double QuarantineThreshold { get; set; } = 80;
    public double AiWeight { get; set; } = 0.3;
    public int MaxEvents { get; set; } = 500;

    public void Validate()
    {
        // Math.Clamp con min > max devuelve min: sin estos topes unos umbrales
        // configurales altos dejarían toda la detección en Allow.
        MonitorThreshold = Math.Clamp(MonitorThreshold, 0, 98);
        BlockThreshold = Math.Clamp(BlockThreshold, MonitorThreshold + 1, 99);
        QuarantineThreshold = Math.Clamp(QuarantineThreshold, BlockThreshold + 1, 100);
        AiWeight = Math.Clamp(AiWeight, 0, 0.5);
        MaxEvents = Math.Clamp(MaxEvents, 50, 5000);
    }
}

public sealed class RuntimeStatus
{
    public bool ServiceRunning { get; set; } = true;
    public bool MonitorActive { get; set; }
    public bool EtwActive { get; set; }
    public bool FirewallActive { get; set; }
    public bool AiReachable { get; set; }
    public string ProtectionState { get; set; } = "starting";
    public DateTimeOffset StartedAt { get; set; }
    public double CpuPercent { get; set; }
    public long WorkingSetBytes { get; set; }
    public long EventsTotal { get; set; }
    public long ThreatsTotal { get; set; }
    public long QuarantinedTotal { get; set; }
    public long BlockedNetworkTotal { get; set; }
    public long DroppedEvents { get; set; }
    public long AiCallsTotal { get; set; }
    public long AiCacheHits { get; set; }
    public List<double> RiskTrend { get; set; } = [];
    public PolicySettings Policy { get; set; } = new();
}

public sealed class CloudClassificationRequest
{
    public string RequestId { get; set; } = string.Empty;
    public string Sha256 { get; set; } = string.Empty;
    public string FileType { get; set; } = string.Empty;
    public long SizeBucket { get; set; }
    public SignatureStatus Signature { get; set; }
    public double Reputation { get; set; }
    public List<string> BehaviorFlags { get; set; } = [];
    public List<string> RuleIds { get; set; } = [];
    public string EventKind { get; set; } = string.Empty;
}

public sealed class CloudClassificationResponse
{
    public string RequestId { get; set; } = string.Empty;
    public string Model { get; set; } = string.Empty;
    public string ChoiceLabel { get; set; } = "INDETERMINATE";
    public double Clean { get; set; }
    public double Suspicious { get; set; }
    public double Malicious { get; set; }
    public double Confidence { get; set; }
    public double SeverityScore { get; set; }
    public bool IsValid { get; set; }
    public string? Error { get; set; }
    public long LatencyMs { get; set; }
    public int InputTokens { get; set; }
}

public static class JsonDefaults
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false,
        Converters = { new JsonStringEnumConverter() }
    };
}
