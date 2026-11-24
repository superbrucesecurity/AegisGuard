using Aegis.Core;
using Aegis.Service;

namespace Aegis.Tests;

public sealed class EventStoreTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "aegis-events-" + Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task MaxEventsIsAppliedWithoutRestarting()
    {
        var store = new EventStore(_root, 5);
        await store.InitializeAsync();
        for (var i = 0; i < 5; i++)
            await store.AppendAsync(new Observation { Kind = EventKind.ManualScan, Subject = $"f{i}" });

        Assert.Equal(5, store.Observations.Count);

        store.SetMaxEvents(2);

        Assert.Equal(2, store.Observations.Count);
        Assert.Equal("f3", store.Observations[0].Subject);
        Assert.Equal("f4", store.Observations[1].Subject);

        store.SetMaxEvents(10);
        Assert.Equal(2, store.Observations.Count);
        Assert.Throws<ArgumentOutOfRangeException>(() => store.SetMaxEvents(0));
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, true); }
        catch (IOException) { /* bloqueo temporal del sistema de archivos */ }
    }
}
