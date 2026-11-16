using Mif.Node.Storage;

namespace Mif.Node.Tests;

public class SnapshotServiceTests
{
    private const string Role = TestNode.EligibleRole;

    [Fact]
    public async Task A_live_upstream_sign_in_issues_a_snapshot_and_makes_the_user_eligible()
    {
        var node = new TestNode();
        var alice = node.Keycloak.AddUser("alice", "finance-approver");
        node.Keycloak.Login(alice, node.Clock.Now, "entra");

        await node.TickAsync();

        var snapshot = Assert.Single(await node.Store.GetCurrentSnapshotsAsync(default));
        Assert.Equal(node.Clock.Now.AddHours(72), snapshot.ExpiresAt);
        Assert.Contains(Role, alice.Roles);
        var verified = await node.Snapshots.VerifyAsync(snapshot.Jws, default);
        Assert.True(verified.Valid, verified.Error);
        Assert.Equal(["finance-approver"], verified.Roles); // internal roles are left out of the snapshot
        Assert.Equal(["snapshot.issued", "passkey.enrolment_required", "eligibility.granted"], await node.AuditTypesAsync());
    }

    [Fact]
    public async Task A_user_without_a_passkey_is_asked_to_enrol_and_one_with_a_passkey_is_not()
    {
        var node = new TestNode();
        var alice = node.Keycloak.AddUser("alice");
        var bob = node.Keycloak.AddUser("bob");
        bob.HasPasskey = true;
        node.Keycloak.Login(alice, node.Clock.Now, "entra");
        node.Keycloak.Login(bob, node.Clock.Now, "entra");

        await node.TickAsync();

        Assert.True(alice.PasskeyEnrolmentRequired);
        Assert.False(bob.PasskeyEnrolmentRequired);
    }

    [Fact]
    public async Task A_passkey_sign_in_never_issues_or_renews_a_snapshot()
    {
        var node = new TestNode();
        var alice = node.Keycloak.AddUser("alice");
        node.Keycloak.Login(alice, node.Clock.Now, "entra");
        await node.TickAsync();
        var original = Assert.Single(await node.Store.GetCurrentSnapshotsAsync(default));

        node.Clock.Advance(TimeSpan.FromHours(48));
        node.Keycloak.Login(alice, node.Clock.Now, identityProvider: null);
        await node.TickAsync();

        Assert.Equal(original, Assert.Single(await node.Store.GetCurrentSnapshotsAsync(default)));
    }

    [Fact]
    public async Task Eligibility_ends_when_the_snapshot_expires_and_the_session_is_ended_during_an_outage()
    {
        var node = new TestNode();
        var alice = node.Keycloak.AddUser("alice");
        node.Keycloak.Login(alice, node.Clock.Now, "entra");
        await node.TickAsync();
        await node.EnterDegradedAsync();

        node.Clock.Advance(TimeSpan.FromHours(72) - TimeSpan.FromSeconds(1));
        await node.TickAsync();
        Assert.Contains(Role, alice.Roles);

        node.Clock.Advance(TimeSpan.FromSeconds(1));
        await node.TickAsync();

        Assert.DoesNotContain(Role, alice.Roles);
        Assert.Equal([alice.Id], node.Keycloak.LoggedOutUsers);
    }

    [Fact]
    public async Task An_expired_snapshot_in_normal_mode_removes_eligibility_but_keeps_the_live_session()
    {
        var node = new TestNode();
        var alice = node.Keycloak.AddUser("alice");
        node.Keycloak.Login(alice, node.Clock.Now, "entra");
        await node.TickAsync();

        node.Clock.Advance(TimeSpan.FromHours(73));
        await node.TickAsync();

        Assert.DoesNotContain(Role, alice.Roles);
        Assert.Empty(node.Keycloak.LoggedOutUsers);
    }

    [Fact]
    public async Task A_new_live_sign_in_extends_eligibility_from_that_sign_in()
    {
        var node = new TestNode();
        var alice = node.Keycloak.AddUser("alice");
        node.Keycloak.Login(alice, node.Clock.Now, "entra");
        await node.TickAsync();

        node.Clock.Advance(TimeSpan.FromHours(24));
        node.Keycloak.Login(alice, node.Clock.Now, "entra");
        await node.TickAsync();

        Assert.Equal(node.Clock.Now.AddHours(72), Assert.Single(await node.Store.GetCurrentSnapshotsAsync(default)).ExpiresAt);
    }

    [Fact]
    public async Task The_same_sign_in_event_is_only_processed_once()
    {
        var node = new TestNode();
        node.Keycloak.Login(node.Keycloak.AddUser("alice"), node.Clock.Now, "entra");

        await node.TickAsync();
        await node.TickAsync();

        Assert.Single(await node.AuditTypesAsync(), t => t == "snapshot.issued");
    }

    [Fact]
    public async Task A_sign_in_older_than_the_snapshot_lifetime_issues_nothing()
    {
        var node = new TestNode();
        var alice = node.Keycloak.AddUser("alice");
        node.Keycloak.Login(alice, node.Clock.Now.AddHours(-80), "entra");

        await node.TickAsync();

        Assert.Empty(await node.Store.GetCurrentSnapshotsAsync(default));
        Assert.DoesNotContain(Role, alice.Roles);
    }

    [Fact]
    public async Task A_backlog_sign_in_expires_relative_to_the_sign_in_not_to_when_it_was_processed()
    {
        var node = new TestNode();
        var signedInAt = node.Clock.Now.AddHours(-70);
        node.Keycloak.Login(node.Keycloak.AddUser("alice"), signedInAt, "entra");

        await node.TickAsync();

        Assert.Equal(signedInAt.AddHours(72), Assert.Single(await node.Store.GetCurrentSnapshotsAsync(default)).ExpiresAt);
    }

    [Fact]
    public async Task A_disabled_user_gets_no_snapshot()
    {
        var node = new TestNode();
        var alice = node.Keycloak.AddUser("alice");
        alice.Enabled = false;
        node.Keycloak.Login(alice, node.Clock.Now, "entra");

        await node.TickAsync();

        Assert.Empty(await node.Store.GetCurrentSnapshotsAsync(default));
    }

    [Fact]
    public async Task Revoking_a_user_removes_eligibility_ends_their_session_and_fails_verification()
    {
        var node = new TestNode();
        var alice = node.Keycloak.AddUser("alice");
        node.Keycloak.Login(alice, node.Clock.Now, "entra");
        await node.TickAsync();
        var jws = (await node.Store.GetCurrentSnapshotsAsync(default))[0].Jws;

        Assert.True(await node.Snapshots.RevokeAsync("alice", "laptop stolen", default));

        Assert.DoesNotContain(Role, alice.Roles);
        Assert.Contains(alice.Id, node.Keycloak.LoggedOutUsers);
        Assert.Equal("revoked", (await node.Snapshots.VerifyAsync(jws, default)).Error);
        await node.TickAsync();
        Assert.DoesNotContain(Role, alice.Roles); // stays revoked across later ticks
    }

    [Fact]
    public async Task A_revocation_is_lifted_only_by_the_next_live_upstream_sign_in()
    {
        var node = new TestNode();
        var alice = node.Keycloak.AddUser("alice");
        node.Keycloak.Login(alice, node.Clock.Now, "entra");
        await node.TickAsync();
        await node.Snapshots.RevokeAsync("alice", "suspected compromise", default);

        node.Clock.Advance(TimeSpan.FromHours(1));
        node.Keycloak.Login(alice, node.Clock.Now, identityProvider: null);
        await node.TickAsync();
        Assert.DoesNotContain(Role, alice.Roles);

        node.Clock.Advance(TimeSpan.FromHours(1));
        node.Keycloak.Login(alice, node.Clock.Now, "entra");
        await node.TickAsync();
        Assert.Contains(Role, alice.Roles);
    }

    [Fact]
    public async Task Revoking_an_unknown_user_reports_not_found()
    {
        Assert.False(await new TestNode().Snapshots.RevokeAsync("nobody", "typo", default));
    }

    [Fact]
    public async Task The_role_granted_by_hand_without_a_snapshot_is_taken_away()
    {
        var node = new TestNode();
        var mallory = node.Keycloak.AddUser("mallory", Role);

        await node.TickAsync();

        Assert.DoesNotContain(Role, mallory.Roles);
        Assert.Equal(["eligibility.removed"], await node.AuditTypesAsync());
    }

    [Fact]
    public async Task A_snapshot_whose_stored_signature_does_not_verify_grants_nothing()
    {
        var node = new TestNode();
        var alice = node.Keycloak.AddUser("alice");
        // Planted directly in the database: right shape, right expiry, but not signed by this node.
        await node.Store.SaveSnapshotAsync(new SnapshotRecord("forged", alice.Id, "alice", node.Clock.Now, node.Clock.Now.AddHours(72), "e30.e30.forged"), default);

        await node.TickAsync();

        Assert.DoesNotContain(Role, alice.Roles);
    }

    [Fact]
    public async Task A_snapshot_unknown_to_this_node_fails_verification_even_with_a_valid_signature()
    {
        var node = new TestNode();
        var jws = node.Signer.Sign(new("never-stored", "u", "alice", "entra", null, node.Clock.Now, node.Clock.Now.AddHours(1), "AAL1", []), node.Clock.Now);

        Assert.Equal("unknown", (await node.Snapshots.VerifyAsync(jws, default)).Error);
    }
}
