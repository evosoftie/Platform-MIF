namespace Mif.Node;

public sealed class MifOptions
{
    /// <summary>Port for read-only endpoints that applications and other nodes may call.</summary>
    public int PublicPort { get; set; } = 8080;

    /// <summary>
    /// Port for operator endpoints (mode override, revocation, audit). They have no login of their own
    /// on purpose: bind this port to loopback and reach it over SSH, so that operating the node never
    /// depends on the identity system it is there to back up.
    /// </summary>
    public int OperatorPort { get; set; } = 8081;

    /// <summary>Npgsql connection string. Empty means an in-memory store (development and tests only).</summary>
    public string? Database { get; set; }

    public KeycloakOptions Keycloak { get; set; } = new();
    public UpstreamOptions Upstream { get; set; } = new();
    public ContinuityOptions Continuity { get; set; } = new();
    public SnapshotOptions Snapshot { get; set; } = new();
}

public sealed class KeycloakOptions
{
    public string BaseUrl { get; set; } = "http://localhost:8080";
    public string Realm { get; set; } = "mif";
    public string ClientId { get; set; } = "mif-node";
    public string ClientSecret { get; set; } = "";
}

public sealed class UpstreamOptions
{
    /// <summary>Alias of the upstream identity provider in the broker realm.</summary>
    public string Alias { get; set; } = "entra";

    /// <summary>OIDC discovery document of the upstream provider.</summary>
    public string DiscoveryUrl { get; set; } = "";

    /// <summary>
    /// Optional synthetic sign-in: a client-credentials request against the upstream token endpoint.
    /// It exercises token issuance, which discovery alone does not.
    /// </summary>
    public string? ProbeTokenUrl { get; set; }
    public string? ProbeClientId { get; set; }
    public string? ProbeClientSecret { get; set; }
    public string? ProbeScope { get; set; }

    public int TimeoutSeconds { get; set; } = 5;
}

public sealed class ContinuityOptions
{
    public int ProbeIntervalSeconds { get; set; } = 15;

    /// <summary>Consecutive failed probes before the node enters degraded mode.</summary>
    public int FailureThreshold { get; set; } = 4;

    /// <summary>Consecutive successful probes before the node returns to normal mode.</summary>
    public int RecoveryThreshold { get; set; } = 8;

    public string NormalFlow { get; set; } = "mif-normal";
    public string ContinuityFlow { get; set; } = "mif-continuity";
}

public sealed class SnapshotOptions
{
    /// <summary>Issuer name written into snapshots. Keep it identical on the active and standby node.</summary>
    public string Issuer { get; set; } = "mif-node";

    /// <summary>
    /// How long after the last live upstream verification a user may sign in with a passkey.
    /// Snapshots are never renewed by a continuity sign-in, so this is also the longest outage a user can ride out.
    /// </summary>
    public double TtlHours { get; set; } = 72;

    /// <summary>Directory holding signing-key.pem and trusted/*.pem (public keys of peer nodes).</summary>
    public string KeyDirectory { get; set; } = "keys";

    /// <summary>Realm role that the continuity sign-in flow requires. Managed only by this service.</summary>
    public string EligibleRole { get; set; } = "continuity-eligible";

    /// <summary>Assurance recorded for a live upstream verification. Raise it only if the upstream enforces MFA.</summary>
    public string UpstreamAssurance { get; set; } = "AAL1";

    /// <summary>Ask users who have no passkey yet to register one at their next sign-in.</summary>
    public bool RequirePasskeyEnrolment { get; set; } = true;

    public int PollSeconds { get; set; } = 5;
}
