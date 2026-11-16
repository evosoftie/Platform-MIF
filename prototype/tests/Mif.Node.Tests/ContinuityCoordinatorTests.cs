using Mif.Node.Continuity;

namespace Mif.Node.Tests;

public class ContinuityCoordinatorTests
{
    private static readonly ProbeResult Up = new(true, "ok");
    private static readonly ProbeResult Down = new(false, "token request returned 503");

    [Fact]
    public async Task An_outage_switches_the_broker_to_the_continuity_flow_and_recovery_switches_it_back()
    {
        var node = new TestNode();

        await node.Continuity.ObserveAsync(Down, default);
        Assert.Equal("mif-normal", node.Keycloak.BrowserFlow);
        await node.Continuity.ObserveAsync(Down, default);
        Assert.Equal("mif-continuity", node.Keycloak.BrowserFlow);
        Assert.Equal(0, node.Keycloak.LogoutAllCalls);

        await node.Continuity.ObserveAsync(Up, default);
        await node.Continuity.ObserveAsync(Up, default);
        Assert.Equal("mif-normal", node.Keycloak.BrowserFlow);
    }

    [Fact]
    public async Task Recovery_ends_all_sessions_once_so_everyone_is_verified_live_again()
    {
        var node = new TestNode();
        await node.EnterDegradedAsync();

        for (var i = 0; i < 5; i++) await node.Continuity.ObserveAsync(Up, default);

        Assert.Equal(1, node.Keycloak.LogoutAllCalls);
        Assert.False(node.Continuity.Status.RevalidationPending);
    }

    [Fact]
    public async Task If_the_broker_is_unreachable_at_recovery_the_switch_back_is_completed_on_a_later_tick()
    {
        var node = new TestNode();
        await node.EnterDegradedAsync();
        await node.Continuity.ObserveAsync(Up, default);

        node.Keycloak.Unreachable = true;
        await Assert.ThrowsAsync<HttpRequestException>(() => node.Continuity.ObserveAsync(Up, default));
        Assert.Equal(ContinuityMode.Normal, node.Continuity.Mode);
        Assert.Equal("mif-continuity", node.Keycloak.BrowserFlow);

        node.Keycloak.Unreachable = false;
        await node.Continuity.ObserveAsync(Up, default);

        Assert.Equal("mif-normal", node.Keycloak.BrowserFlow);
        Assert.Equal(1, node.Keycloak.LogoutAllCalls);
    }

    [Fact]
    public async Task A_sign_in_flow_changed_behind_the_nodes_back_is_put_right()
    {
        var node = new TestNode();
        node.Keycloak.BrowserFlow = "mif-continuity"; // e.g. left over from a restore, or changed by hand

        await node.Continuity.ObserveAsync(Up, default);

        Assert.Equal("mif-normal", node.Keycloak.BrowserFlow);
    }

    [Fact]
    public async Task The_mode_survives_a_restart_of_the_node()
    {
        var node = new TestNode();
        await node.EnterDegradedAsync();
        await node.Continuity.SetOverrideAsync(ModeOverride.ForceDegraded, "holding until vendor confirms", default);

        var restarted = new ContinuityCoordinator(node.Keycloak, node.Store, node.Audit, Microsoft.Extensions.Options.Options.Create(node.Options), node.Clock);
        await restarted.LoadAsync(default);

        Assert.Equal(ContinuityMode.Degraded, restarted.Mode);
        Assert.Equal(ModeOverride.ForceDegraded, restarted.Status.Override);
    }

    [Fact]
    public async Task An_operator_can_force_degraded_mode_for_a_drill_and_release_it()
    {
        var node = new TestNode();

        await node.Continuity.SetOverrideAsync(ModeOverride.ForceDegraded, "quarterly drill", default);
        Assert.Equal("mif-continuity", node.Keycloak.BrowserFlow);
        await node.Continuity.ObserveAsync(Up, default);
        Assert.Equal("mif-continuity", node.Keycloak.BrowserFlow);

        await node.Continuity.SetOverrideAsync(ModeOverride.Auto, "drill over", default);
        Assert.Equal("mif-normal", node.Keycloak.BrowserFlow);
        Assert.Equal(1, node.Keycloak.LogoutAllCalls);
    }

    [Fact]
    public async Task Every_mode_change_is_audited_with_its_reason()
    {
        var node = new TestNode();
        await node.EnterDegradedAsync();

        var change = Assert.Single(await node.Store.GetAuditAsync(100, default), r => r.Type == "continuity.mode_changed");
        Assert.Contains("upstream failed 2 consecutive probes: down", change.Data);
        Assert.Contains("\"to\":\"Degraded\"", change.Data);
    }
}
