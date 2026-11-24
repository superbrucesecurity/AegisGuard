using Aegis.Core;

namespace Aegis.Service;

public sealed class RuntimeState
{
    private readonly object _gate = new();
    public DateTimeOffset StartedAt { get; } = DateTimeOffset.UtcNow;
    public PolicySettings Policy { get; private set; } = new();
    public bool MonitorActive { get; set; }
    public bool EtwActive { get; set; }
    public bool AiReachable { get; set; }

    public long EventsTotal;
    public long ThreatsTotal;
    public long QuarantinedTotal;
    public long BlockedNetworkTotal;
    public long DroppedEvents;
    public long AiCacheHits;
    public readonly List<double> RiskTrend = [];

    public void UpdatePolicy(PolicySettings policy)
    {
        policy.Validate();
        lock (_gate) Policy = policy;
    }

    public PolicySettings GetPolicy()
    {
        lock (_gate) return new PolicySettings
        {
            AiEnabled = Policy.AiEnabled,
            LearningMode = Policy.LearningMode,
            AutoQuarantine = Policy.AutoQuarantine,
            AutoBlockNetwork = Policy.AutoBlockNetwork,
            MonitorThreshold = Policy.MonitorThreshold,
            BlockThreshold = Policy.BlockThreshold,
            QuarantineThreshold = Policy.QuarantineThreshold,
            AiWeight = Policy.AiWeight,
            MaxEvents = Policy.MaxEvents
        };
    }

    public void Record(DecisionResult decision)
    {
        if (decision.Verdict != Verdict.Allow) Interlocked.Increment(ref ThreatsTotal);
        if (decision.Verdict is Verdict.Quarantine or Verdict.Block) Interlocked.Increment(ref QuarantinedTotal);
        lock (_gate)
        {
            RiskTrend.Add(decision.Risk);
            if (RiskTrend.Count > 40) RiskTrend.RemoveAt(0);
        }
    }

    public RuntimeStatus Snapshot(IAiClassifier ai, bool firewallActive)
    {
        using var process = System.Diagnostics.Process.GetCurrentProcess();
        var policy = GetPolicy();
        double cpu;
        try
        {
            cpu = process.TotalProcessorTime.TotalMilliseconds / Math.Max(1, (DateTime.UtcNow - process.StartTime.ToUniversalTime()).TotalMilliseconds) * 100 / Environment.ProcessorCount;
        }
        catch { cpu = 0; }

        List<double> trend;
        lock (_gate) trend = [.. RiskTrend];

        string state;
        // Sin ETW se mantiene el sondeo de procesos y los watchers, pero la
        // telemetría es menos precisa: el estado debe reflejarlo, no "protegido".
        if (!MonitorActive || !EtwActive) state = "degraded";
        else if (!firewallActive) state = "limited";
        else if (policy.LearningMode) state = "learning";
        else state = "protected";

        return new RuntimeStatus
        {
            ServiceRunning = true,
            MonitorActive = MonitorActive,
            EtwActive = EtwActive,
            FirewallActive = firewallActive,
            AiReachable = AiReachable,
            ProtectionState = state,
            StartedAt = StartedAt,
            CpuPercent = Math.Round(cpu, 2),
            WorkingSetBytes = process.WorkingSet64,
            EventsTotal = Interlocked.Read(ref EventsTotal),
            ThreatsTotal = Interlocked.Read(ref ThreatsTotal),
            QuarantinedTotal = Interlocked.Read(ref QuarantinedTotal),
            BlockedNetworkTotal = Interlocked.Read(ref BlockedNetworkTotal),
            DroppedEvents = Interlocked.Read(ref DroppedEvents),
            AiCallsTotal = ai is LiquidGatewayClient client ? client.Calls : 0,
            AiCacheHits = ai is LiquidGatewayClient c2 ? c2.CacheHits : 0,
            RiskTrend = trend,
            Policy = policy
        };
    }
}
