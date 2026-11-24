using Aegis.Core;
using Aegis.Service;

namespace Aegis.Tests;

public sealed class PriorityObservationQueueTests
{
    [Fact]
    public async Task CriticalEventsAreReadBeforeNormalEvents()
    {
        using var cts = new CancellationTokenSource();
        var queue = new PriorityObservationQueue(coalesceMilliseconds: 0);
        Assert.True(queue.TryEnqueue(new Observation { Kind = EventKind.NetworkConnection, Subject = "normal" }));
        Assert.True(queue.TryEnqueue(new Observation
        {
            Kind = EventKind.PersistenceChanged,
            Subject = "critico",
            Source = "canary-watcher"
        }));

        await using var reader = queue.ReadAllAsync(cts.Token).GetAsyncEnumerator();
        Assert.True(await reader.MoveNextAsync());
        Assert.Equal("critico", reader.Current.Subject);
        Assert.True(await reader.MoveNextAsync());
        Assert.Equal("normal", reader.Current.Subject);
    }

    [Fact]
    public void CoalescingAndNormalDropsAreCountedSeparately()
    {
        var queue = new PriorityObservationQueue(normalCapacity: 2);
        var observation = new Observation { Kind = EventKind.FileCreated, Subject = "mismo" };

        Assert.True(queue.TryEnqueue(observation));
        Assert.False(queue.TryEnqueue(observation));
        Assert.Equal(1, queue.Coalesced);
        Assert.Equal(0, queue.Dropped);

        var dropped = new PriorityObservationQueue(normalCapacity: 1, coalesceMilliseconds: 0);
        Assert.True(dropped.TryEnqueue(new Observation { Subject = "uno" }));
        Assert.False(dropped.TryEnqueue(new Observation { Subject = "dos" }));
        Assert.Equal(1, dropped.DroppedNormal);
        Assert.Equal(1, dropped.Dropped);
    }

    [Fact]
    public void CoalescedDuplicatesAreNotReportedAsDropped()
    {
        var queue = new PriorityObservationQueue();
        var observation = new Observation { Kind = EventKind.FileModified, Subject = "duplicado" };

        Assert.True(queue.TryEnqueue(observation, out var firstCoalesced));
        Assert.False(firstCoalesced);
        Assert.False(queue.TryEnqueue(observation, out var duplicateCoalesced));
        Assert.True(duplicateCoalesced);
        Assert.Equal(1, queue.Coalesced);
        Assert.Equal(0, queue.Dropped);

        var full = new PriorityObservationQueue(normalCapacity: 1, coalesceMilliseconds: 0);
        Assert.True(full.TryEnqueue(new Observation { Subject = "uno" }, out var first));
        Assert.False(first);
        Assert.False(full.TryEnqueue(new Observation { Subject = "dos" }, out var droppedCoalesced));
        Assert.False(droppedCoalesced);
        Assert.Equal(1, full.DroppedNormal);
    }

    [Fact]
    public async Task CriticalQueueDropsOldestAndKeepsNewest()
    {
        using var cts = new CancellationTokenSource();
        var queue = new PriorityObservationQueue(criticalCapacity: 1, coalesceMilliseconds: 0);
        Assert.True(queue.TryEnqueue(new Observation { Subject = "antiguo", Source = "canary" }));
        Assert.True(queue.TryEnqueue(new Observation { Subject = "reciente", Source = "canary" }));
        Assert.Equal(1, queue.DroppedCritical);

        await using var reader = queue.ReadAllAsync(cts.Token).GetAsyncEnumerator();
        Assert.True(await reader.MoveNextAsync());
        Assert.Equal("reciente", reader.Current.Subject);
    }
}
