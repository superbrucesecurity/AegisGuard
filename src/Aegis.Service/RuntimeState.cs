using Aegis.Core;

namespace Aegis.Service;

public sealed class RuntimeState
{
    private readonly object _gate = new();
    public DateTimeOffset StartedAt { get; } = DateTimeOffset.UtcNow;
    public PolicySettings Policy { get; private set; } = new();
    public bool MonitorActive { get; set; }
    public bool EtwActive { get; set; }
    public string ServiceName { get; set; } = "AegisGuardSvc";
    public bool ManagedByScm { get; set; }

    public long EventsTotal;
    public long ThreatsTotal;
    public long QuarantinedTotal;
    public long BlockedTotal;
    public long BlockedNetworkTotal;
    public long DroppedEvents;
    public long CoalescedEvents;
    public bool WatchersDegraded;
    public bool QueueSaturated;
    public int CriticalQueueDepth;
    public int NormalQueueDepth;
    public double OldestQueuedSeconds;
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
            LearningMode = Policy.LearningMode,
            AutoQuarantine = Policy.AutoQuarantine,
            AutoBlockNetwork = Policy.AutoBlockNetwork,
            MonitorThreshold = Policy.MonitorThreshold,
            BlockThreshold = Policy.BlockThreshold,
            QuarantineThreshold = Policy.QuarantineThreshold,
            MaxEvents = Policy.MaxEvents
        };
    }

    public void Record(DecisionResult decision)
    {
        if (decision.Verdict != Verdict.Allow) Interlocked.Increment(ref ThreatsTotal);
        if (decision.Verdict == Verdict.Quarantine) Interlocked.Increment(ref QuarantinedTotal);
        else if (decision.Verdict == Verdict.Block) Interlocked.Increment(ref BlockedTotal);
        lock (_gate)
        {
            RiskTrend.Add(decision.Risk);
            if (RiskTrend.Count > 40) RiskTrend.RemoveAt(0);
        }
    }

    public RuntimeStatus Snapshot(bool firewallActive)
    {
        using var process = System.Diagnostics.Process.GetCurrentProcess();
        var policy = GetPolicy();
        double cpu;
        try
        {
            cpu = process.TotalProcessorTime.TotalMilliseconds /
                  Math.Max(1, (DateTime.UtcNow - process.StartTime.ToUniversalTime()).TotalMilliseconds) *
                  100 / Environment.ProcessorCount;
        }
        catch { cpu = 0; }

        List<double> trend;
        lock (_gate) trend = [.. RiskTrend];

        string state;
        // Nunca informar de protección completa si se descartan eventos, hay
        // sensores caídos o la antigüedad de la cola indica pérdida de visibilidad.
        var dropped = Interlocked.Read(ref DroppedEvents);
        if (!MonitorActive || !EtwActive || dropped > 0 || WatchersDegraded || QueueSaturated ||
            OldestQueuedSeconds > 30) state = "degraded";
        else if (!firewallActive) state = "limited";
        else if (policy.LearningMode) state = "learning";
        else state = "protected";

        return new RuntimeStatus
        {
            ServiceRunning = true,
            ServiceName = ServiceName,
            ManagedByScm = ManagedByScm,
            MonitorActive = MonitorActive,
            EtwActive = EtwActive,
            FirewallActive = firewallActive,
            ProtectionState = state,
            StartedAt = StartedAt,
            CpuPercent = Math.Round(cpu, 2),
            WorkingSetBytes = process.WorkingSet64,
            EventsTotal = Interlocked.Read(ref EventsTotal),
            ThreatsTotal = Interlocked.Read(ref ThreatsTotal),
            QuarantinedTotal = Interlocked.Read(ref QuarantinedTotal),
            BlockedTotal = Interlocked.Read(ref BlockedTotal),
            BlockedNetworkTotal = Interlocked.Read(ref BlockedNetworkTotal),
            DroppedEvents = dropped,
            CoalescedEvents = Interlocked.Read(ref CoalescedEvents),
            CriticalQueueDepth = CriticalQueueDepth,
            NormalQueueDepth = NormalQueueDepth,
            OldestQueuedSeconds = Math.Round(OldestQueuedSeconds, 1),
            RiskTrend = trend,
            Policy = policy
        };
    }
}
