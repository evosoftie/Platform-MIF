using Microsoft.Extensions.Options;
using Mif.Node.Continuity;
using Mif.Node.Snapshots;
using Mif.Node.Storage;

namespace Mif.Node;

/// <summary>Runs the two loops of the node: watch the upstream, and keep snapshots and eligibility current.</summary>
public sealed class NodeWorker(
    IMifStore store,
    ContinuityCoordinator continuity,
    IUpstreamProbe probe,
    SnapshotService snapshots,
    IOptions<MifOptions> options,
    ILogger<NodeWorker> log) : BackgroundService
{
    public bool Ready { get; private set; }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        await RetryAsync("initialise store", async () =>
        {
            await store.InitializeAsync(ct);
            await continuity.LoadAsync(ct);
        }, ct);
        Ready = true;

        await Task.WhenAll(
            LoopAsync("continuity", options.Value.Continuity.ProbeIntervalSeconds, async () =>
                await continuity.ObserveAsync(await probe.ProbeAsync(ct), ct), ct),
            LoopAsync("snapshots", options.Value.Snapshot.PollSeconds, async () =>
            {
                await snapshots.ProcessLoginEventsAsync(ct);
                await snapshots.ReconcileEligibilityAsync(ct);
            }, ct));
    }

    private async Task LoopAsync(string name, int intervalSeconds, Func<Task> tick, CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(Math.Max(1, intervalSeconds)));
        do
        {
            try
            {
                await tick();
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                // The broker or database being briefly unreachable must not stop the loop: every tick is idempotent.
                log.LogWarning("{Loop} tick failed, will retry: {Message}", name, e.Message);
            }
        }
        while (await timer.WaitForNextTickAsync(ct));
    }

    private async Task RetryAsync(string what, Func<Task> action, CancellationToken ct)
    {
        while (true)
        {
            try
            {
                await action();
                return;
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                log.LogWarning("Could not {What} yet, retrying in 2s: {Message}", what, e.Message);
                await Task.Delay(TimeSpan.FromSeconds(2), ct);
            }
        }
    }
}
