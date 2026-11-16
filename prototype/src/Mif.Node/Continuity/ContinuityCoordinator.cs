using Microsoft.Extensions.Options;
using Mif.Node.Audit;
using Mif.Node.Keycloak;
using Mif.Node.Storage;

namespace Mif.Node.Continuity;

public sealed record ContinuityStatus(
    ContinuityMode Mode,
    ModeOverride Override,
    DateTimeOffset? Since,
    bool? UpstreamHealthy,
    string? UpstreamDetail,
    DateTimeOffset? LastProbeAt,
    int ConsecutiveFailures,
    bool RevalidationPending);

/// <summary>
/// Owns the operating mode and makes the broker follow it. The mode decision is persisted first and
/// applied to Keycloak by <see cref="EnforceAsync"/>, which is safe to repeat, so a broker that is
/// briefly unreachable catches up on the next tick instead of being left in the wrong flow.
/// </summary>
public sealed class ContinuityCoordinator(
    IKeycloakAdmin keycloak,
    IMifStore store,
    AuditLog audit,
    IOptions<MifOptions> options,
    TimeProvider time)
{
    private const string AutoModeKey = "continuity.auto_mode";
    private const string OverrideKey = "continuity.override";
    private const string SinceKey = "continuity.since";
    private const string RevalidationKey = "continuity.revalidation_pending";

    private readonly ContinuityOptions _options = options.Value.Continuity;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private ContinuityStateMachine _machine = new(options.Value.Continuity.FailureThreshold, options.Value.Continuity.RecoveryThreshold);
    private DateTimeOffset? _since;
    private bool _revalidationPending;
    private ProbeResult? _lastProbe;
    private DateTimeOffset? _lastProbeAt;

    public ContinuityMode Mode => _machine.Mode;

    public ContinuityStatus Status => new(
        _machine.Mode, _machine.Override, _since, _lastProbe?.Healthy, _lastProbe?.Detail, _lastProbeAt,
        _machine.ConsecutiveFailures, _revalidationPending);

    /// <summary>Restores the mode from before a restart, so a restart mid-outage does not end the outage handling.</summary>
    public async Task LoadAsync(CancellationToken ct)
    {
        var mode = Enum.TryParse<ContinuityMode>(await store.GetStateAsync(AutoModeKey, ct), out var m) ? m : ContinuityMode.Normal;
        var over = Enum.TryParse<ModeOverride>(await store.GetStateAsync(OverrideKey, ct), out var o) ? o : ModeOverride.Auto;
        _machine = new ContinuityStateMachine(_options.FailureThreshold, _options.RecoveryThreshold, mode, over);
        _since = DateTimeOffset.TryParse(await store.GetStateAsync(SinceKey, ct), out var since) ? since : null;
        _revalidationPending = await store.GetStateAsync(RevalidationKey, ct) == "true";
    }

    public async Task ObserveAsync(ProbeResult probe, CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            _lastProbe = probe;
            _lastProbeAt = time.GetUtcNow();
            var transition = _machine.Observe(probe.Healthy, probe.Detail);
            if (transition is not null) await RecordAsync(transition, ct);
            await EnforceLockedAsync(ct);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<ContinuityStatus> SetOverrideAsync(ModeOverride value, string reason, CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            var transition = _machine.SetOverride(value, reason);
            await store.SetStateAsync(OverrideKey, value.ToString(), ct);
            await audit.WriteAsync("continuity.override_set", null, new { @override = value.ToString(), reason }, ct);
            if (transition is not null) await RecordAsync(transition, ct);
            await EnforceLockedAsync(ct);
            return Status;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task EnforceAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            await EnforceLockedAsync(ct);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task RecordAsync(ModeTransition transition, CancellationToken ct)
    {
        _since = time.GetUtcNow();
        // Sessions opened with a passkey during the outage must not outlive it: once the upstream is
        // back, everyone signs in again and is verified live.
        _revalidationPending = transition.To == ContinuityMode.Normal;
        await store.SetStateAsync(AutoModeKey, _machine.AutoMode.ToString(), ct);
        await store.SetStateAsync(SinceKey, _since.Value.ToString("O"), ct);
        await store.SetStateAsync(RevalidationKey, _revalidationPending ? "true" : "false", ct);
        await audit.WriteAsync("continuity.mode_changed", null,
            new { from = transition.From.ToString(), to = transition.To.ToString(), reason = transition.Reason }, ct);
    }

    private async Task EnforceLockedAsync(CancellationToken ct)
    {
        var wanted = _machine.Mode == ContinuityMode.Degraded ? _options.ContinuityFlow : _options.NormalFlow;
        var actual = await keycloak.GetBrowserFlowAsync(ct);
        if (actual != wanted)
        {
            await keycloak.SetBrowserFlowAsync(wanted, ct);
            await audit.WriteAsync("broker.sign_in_flow_set", null, new { from = actual, to = wanted }, ct);
        }

        if (_revalidationPending && _machine.Mode == ContinuityMode.Normal)
        {
            await keycloak.LogoutAllAsync(ct);
            _revalidationPending = false;
            await store.SetStateAsync(RevalidationKey, "false", ct);
            await audit.WriteAsync("broker.sessions_ended", null, new { reason = "live re-verification after continuity" }, ct);
        }
    }
}
