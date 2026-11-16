using Mif.Node.Continuity;

namespace Mif.Node.Tests;

public class ContinuityStateMachineTests
{
    [Fact]
    public void Degraded_mode_starts_only_after_the_failure_threshold()
    {
        var machine = new ContinuityStateMachine(failureThreshold: 3, recoveryThreshold: 2);

        Assert.Null(machine.Observe(false, "timeout"));
        Assert.Null(machine.Observe(false, "timeout"));
        var transition = machine.Observe(false, "timeout");

        Assert.Equal(new(ContinuityMode.Normal, ContinuityMode.Degraded), (transition!.From, transition.To));
        Assert.Contains("timeout", transition.Reason);
    }

    [Fact]
    public void A_flapping_upstream_does_not_change_the_mode()
    {
        var machine = new ContinuityStateMachine(failureThreshold: 3, recoveryThreshold: 3);

        foreach (var healthy in new[] { false, false, true, false, false, true, false, false, true })
            Assert.Null(machine.Observe(healthy, "flap"));

        Assert.Equal(ContinuityMode.Normal, machine.Mode);
    }

    [Fact]
    public void Recovery_needs_a_run_of_successes_and_a_single_failure_restarts_the_count()
    {
        var machine = new ContinuityStateMachine(failureThreshold: 1, recoveryThreshold: 3);
        machine.Observe(false, "down");

        Assert.Null(machine.Observe(true, "up"));
        Assert.Null(machine.Observe(true, "up"));
        Assert.Null(machine.Observe(false, "down"));
        Assert.Null(machine.Observe(true, "up"));
        Assert.Null(machine.Observe(true, "up"));
        var transition = machine.Observe(true, "up");

        Assert.Equal(ContinuityMode.Normal, transition!.To);
    }

    [Fact]
    public void An_operator_override_wins_over_the_probes_until_it_is_cleared()
    {
        var machine = new ContinuityStateMachine(failureThreshold: 1, recoveryThreshold: 1);

        Assert.Equal(ContinuityMode.Degraded, machine.SetOverride(ModeOverride.ForceDegraded, "drill")!.To);
        Assert.Null(machine.Observe(true, "up"));
        Assert.Equal(ContinuityMode.Degraded, machine.Mode);

        Assert.Equal(ContinuityMode.Normal, machine.SetOverride(ModeOverride.Auto, "drill over")!.To);
    }

    [Fact]
    public void Forcing_normal_holds_the_mode_while_the_probes_fail()
    {
        var machine = new ContinuityStateMachine(failureThreshold: 1, recoveryThreshold: 1);
        machine.SetOverride(ModeOverride.ForceNormal, "probe is known to be wrong");

        Assert.Null(machine.Observe(false, "down"));
        Assert.Equal(ContinuityMode.Normal, machine.Mode);

        Assert.Equal(ContinuityMode.Degraded, machine.SetOverride(ModeOverride.Auto, "back to automatic")!.To);
    }
}
