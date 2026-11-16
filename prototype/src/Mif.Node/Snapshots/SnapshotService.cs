using Microsoft.Extensions.Options;
using Mif.Node.Audit;
using Mif.Node.Continuity;
using Mif.Node.Keycloak;
using Mif.Node.Storage;

namespace Mif.Node.Snapshots;

public sealed record VerifyResult(bool Valid, string? Error, string? Subject, string? Username, DateTimeOffset? VerifiedAt, DateTimeOffset? ExpiresAt, IReadOnlyList<string>? Roles);

/// <summary>
/// Turns live upstream sign-ins into signed identity snapshots, and keeps the broker's
/// "continuity-eligible" role equal to "holds a valid, unexpired, unrevoked snapshot".
/// </summary>
public sealed class SnapshotService(
    IKeycloakAdmin keycloak,
    IMifStore store,
    SnapshotSigner signer,
    AuditLog audit,
    ContinuityCoordinator continuity,
    IOptions<MifOptions> options,
    TimeProvider time,
    ILogger<SnapshotService> log)
{
    private readonly SnapshotOptions _options = options.Value.Snapshot;
    private readonly string _upstreamAlias = options.Value.Upstream.Alias;

    /// <summary>Issues snapshots for sign-ins not seen before. Returns how many were issued.</summary>
    public async Task<int> ProcessLoginEventsAsync(CancellationToken ct)
    {
        var issued = 0;
        foreach (var login in (await keycloak.GetLoginEventsAsync(200, ct)).OrderBy(e => e.Time))
        {
            // Only a sign-in the upstream verified live may create or renew a snapshot. A passkey
            // sign-in never does, otherwise continuity access would renew itself indefinitely.
            if (login.IdentityProvider != _upstreamAlias) continue;
            if (login.Time + Ttl <= time.GetUtcNow()) continue;
            if (!await store.TryMarkEventProcessedAsync(login.Id, login.Time, ct)) continue;
            if (await IssueAsync(login, ct) is not null) issued++;
        }
        return issued;
    }

    private TimeSpan Ttl => TimeSpan.FromHours(_options.TtlHours);

    private async Task<SnapshotRecord?> IssueAsync(LoginEvent login, CancellationToken ct)
    {
        var user = await keycloak.GetUserAsync(login.UserId, ct);
        if (user is null || !user.Enabled)
        {
            log.LogWarning("No snapshot for login {EventId}: user {UserId} is missing or disabled", login.Id, login.UserId);
            return null;
        }

        var roles = (await keycloak.GetRealmRolesAsync(user.Id, ct)).Where(IsBusinessRole).Order().ToList();
        var claims = new SnapshotClaims(
            Guid.NewGuid().ToString(), user.Id, user.Username, _upstreamAlias, user.UpstreamSubject,
            login.Time, login.Time + Ttl, _options.UpstreamAssurance, roles);
        var record = new SnapshotRecord(claims.Jti, user.Id, user.Username, claims.VerifiedAt, claims.ExpiresAt, signer.Sign(claims, time.GetUtcNow()));
        await store.SaveSnapshotAsync(record, ct);
        await audit.WriteAsync("snapshot.issued", user.Username,
            new { jti = record.Jti, verified_at = record.VerifiedAt, expires_at = record.ExpiresAt, source = _upstreamAlias, roles, login_event = login.Id }, ct);

        if (_options.RequirePasskeyEnrolment && !await keycloak.HasPasskeyAsync(user.Id, ct))
        {
            await keycloak.RequirePasskeyEnrolmentAsync(user.Id, ct);
            await audit.WriteAsync("passkey.enrolment_required", user.Username, new { }, ct);
        }
        return record;
    }

    private bool IsBusinessRole(string role) =>
        role != _options.EligibleRole && role is not ("offline_access" or "uma_authorization") && !role.StartsWith("default-roles-", StringComparison.Ordinal);

    /// <summary>
    /// Makes role membership match the set of valid snapshots, in both directions. Anyone holding the
    /// role without a valid snapshot loses it, including a role granted by hand in the broker.
    /// </summary>
    public async Task ReconcileEligibilityAsync(CancellationToken ct)
    {
        var now = time.GetUtcNow();
        var current = (await store.GetCurrentSnapshotsAsync(ct)).ToDictionary(s => s.UserId);
        var eligible = current.Values.Where(s => Ineligibility(s, now) is null).Select(s => s.UserId).ToHashSet();
        var members = (await keycloak.GetRoleMemberIdsAsync(_options.EligibleRole, ct)).ToHashSet();

        foreach (var userId in eligible.Except(members))
        {
            await keycloak.AddRealmRoleAsync(userId, _options.EligibleRole, ct);
            await audit.WriteAsync("eligibility.granted", current[userId].Username, new { jti = current[userId].Jti, expires_at = current[userId].ExpiresAt }, ct);
        }

        foreach (var userId in members.Except(eligible))
        {
            var snapshot = current.GetValueOrDefault(userId);
            var reason = snapshot is null ? "no_snapshot" : Ineligibility(snapshot, now)!;
            await keycloak.RemoveRealmRoleAsync(userId, _options.EligibleRole, ct);
            // During an outage the role is the only thing keeping the user signed in, so end the session with it.
            var endSession = continuity.Mode == ContinuityMode.Degraded;
            if (endSession) await keycloak.LogoutUserAsync(userId, ct);
            await audit.WriteAsync("eligibility.removed", snapshot?.Username ?? userId, new { reason, jti = snapshot?.Jti, session_ended = endSession }, ct);
        }
    }

    private string? Ineligibility(SnapshotRecord snapshot, DateTimeOffset now)
    {
        if (snapshot.RevokedAt is not null) return "revoked";
        if (snapshot.ExpiresAt <= now) return "expired";
        var validation = signer.Validate(snapshot.Jws, now);
        return validation.Valid ? null : $"invalid:{validation.Error}";
    }

    /// <summary>
    /// Local revocation for the time the upstream cannot tell us an account was disabled. It holds
    /// until the upstream next verifies the user live, which issues a fresh snapshot.
    /// </summary>
    public async Task<bool> RevokeAsync(string username, string reason, CancellationToken ct)
    {
        var user = await keycloak.FindUserByUsernameAsync(username, ct);
        if (user is null) return false;
        var revoked = await store.RevokeUserSnapshotsAsync(user.Id, time.GetUtcNow(), reason, ct);
        await keycloak.LogoutUserAsync(user.Id, ct);
        await audit.WriteAsync("snapshot.revoked", user.Username, new { reason, snapshots = revoked }, ct);
        await ReconcileEligibilityAsync(ct);
        return true;
    }

    /// <summary>Verifies a snapshot presented by an application or a peer node.</summary>
    public async Task<VerifyResult> VerifyAsync(string jws, CancellationToken ct)
    {
        var validation = signer.Validate(jws, time.GetUtcNow());
        if (!validation.Valid) return new(false, validation.Error, null, null, null, null, null);
        var token = validation.Token!;
        var stored = await store.GetSnapshotAsync(token.Id, ct);
        if (stored is null) return new(false, "unknown", null, null, null, null, null);
        if (stored.RevokedAt is not null) return new(false, "revoked", null, null, null, null, null);
        return new(true, null, token.Subject, stored.Username, stored.VerifiedAt, stored.ExpiresAt,
            [.. token.Claims.Where(c => c.Type == "roles").Select(c => c.Value)]);
    }
}
