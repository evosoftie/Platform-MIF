namespace Mif.Node.Continuity;

public enum ContinuityMode { Normal, Degraded }

public enum ModeOverride { Auto, ForceDegraded, ForceNormal }

public sealed record ModeTransition(ContinuityMode From, ContinuityMode To, string Reason);

/// <summary>
/// Decides the operating mode from a stream of upstream probe results. Thresholds on both edges
/// keep a flapping upstream from flipping the mode, and an operator override always wins.
/// </summary>
public sealed class ContinuityStateMachine(
    int failureThreshold,
    int recoveryThreshold,
    ContinuityMode initialAutoMode = ContinuityMode.Normal,
    ModeOverride initialOverride = ModeOverride.Auto)
{
    public ContinuityMode AutoMode { get; private set; } = initialAutoMode;
    public ModeOverride Override { get; private set; } = initialOverride;
    public int ConsecutiveFailures { get; private set; }
    public int ConsecutiveSuccesses { get; private set; }

    /// <summary>The mode in force: the operator override if set, otherwise what the probes say.</summary>
    public ContinuityMode Mode => Override switch
    {
        ModeOverride.ForceDegraded => ContinuityMode.Degraded,
        ModeOverride.ForceNormal => ContinuityMode.Normal,
        _ => AutoMode,
    };

    /// <summary>Feeds one probe result. Returns a transition only when the mode in force changed.</summary>
    public ModeTransition? Observe(bool healthy, string detail)
    {
        var before = Mode;
        if (healthy)
        {
            ConsecutiveSuccesses++;
            ConsecutiveFailures = 0;
            if (AutoMode == ContinuityMode.Degraded && ConsecutiveSuccesses >= recoveryThreshold) AutoMode = ContinuityMode.Normal;
        }
        else
        {
            ConsecutiveFailures++;
            ConsecutiveSuccesses = 0;
            if (AutoMode == ContinuityMode.Normal && ConsecutiveFailures >= failureThreshold) AutoMode = ContinuityMode.Degraded;
        }

        return Mode == before ? null : new ModeTransition(before, Mode, healthy
            ? $"upstream healthy for {ConsecutiveSuccesses} consecutive probes"
            : $"upstream failed {ConsecutiveFailures} consecutive probes: {detail}");
    }

    public ModeTransition? SetOverride(ModeOverride value, string reason)
    {
        var before = Mode;
        Override = value;
        return Mode == before ? null : new ModeTransition(before, Mode, $"operator override {value}: {reason}");
    }
}
