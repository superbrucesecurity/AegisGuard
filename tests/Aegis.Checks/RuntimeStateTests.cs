using Aegis.Core;
using Aegis.Service;

namespace Aegis.Tests;

public sealed class RuntimeStateTests
{
    [Fact]
    public void BlockAndQuarantineAreIndependentCounters()
    {
        var state = new RuntimeState();
        state.Record(new DecisionResult { Verdict = Verdict.Quarantine, Risk = 90 });
        state.Record(new DecisionResult { Verdict = Verdict.Block, Risk = 80 });
        state.Record(new DecisionResult { Verdict = Verdict.Block, Risk = 80 });

        var snapshot = state.Snapshot(true);

        Assert.Equal(3, snapshot.ThreatsTotal);
        Assert.Equal(1, snapshot.QuarantinedTotal);
        Assert.Equal(2, snapshot.BlockedTotal);
    }

    [Fact]
    public void DroppedEventsOrDegradedWatchersNeverShowFullProtection()
    {
        var state = new RuntimeState
        {
            MonitorActive = true,
            EtwActive = true
        };
        state.UpdatePolicy(new PolicySettings { LearningMode = false });
        Assert.Equal("protected", state.Snapshot(true).ProtectionState);

        state.DroppedEvents = 1;
        Assert.Equal("degraded", state.Snapshot(true).ProtectionState);

        state.DroppedEvents = 0;
        state.WatchersDegraded = true;
        Assert.Equal("degraded", state.Snapshot(true).ProtectionState);

        state.WatchersDegraded = false;
        state.QueueSaturated = true;
        Assert.Equal("degraded", state.Snapshot(true).ProtectionState);

        state.QueueSaturated = false;
        state.OldestQueuedSeconds = 31;
        Assert.Equal("degraded", state.Snapshot(true).ProtectionState);
    }
}
