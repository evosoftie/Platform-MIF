using System.Security.Cryptography;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Mif.Node.Audit;
using Mif.Node.Continuity;
using Mif.Node.Keycloak;
using Mif.Node.Snapshots;
using Mif.Node.Storage;

namespace Mif.Node.Tests;

public sealed class TestClock(DateTimeOffset start) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = start;
    public override DateTimeOffset GetUtcNow() => Now;
    public void Advance(TimeSpan by) => Now += by;
}

/// <summary>In-memory stand-in for the broker's admin API, recording what the node did to it.</summary>
public sealed class FakeKeycloak : IKeycloakAdmin
{
    public sealed class User(string id, string username)
    {
        public string Id { get; } = id;
        public string Username { get; } = username;
        public bool Enabled { get; set; } = true;
        public HashSet<string> Roles { get; } = ["default-roles-mif", "offline_access"];
        public bool HasPasskey { get; set; }
        public bool PasskeyEnrolmentRequired { get; set; }
    }

    public Dictionary<string, User> Users { get; } = [];
    public List<LoginEvent> Events { get; } = [];
    public string BrowserFlow { get; set; } = "mif-normal";
    public int LogoutAllCalls { get; private set; }
    public List<string> LoggedOutUsers { get; } = [];
    public bool Unreachable { get; set; }

    public User AddUser(string username, params string[] roles)
    {
        var user = new User($"id-{username}", username);
        foreach (var role in roles) user.Roles.Add(role);
        return Users[user.Id] = user;
    }

    public LoginEvent Login(User user, DateTimeOffset at, string? identityProvider)
    {
        var login = new LoginEvent(Guid.NewGuid().ToString(), at, user.Id, identityProvider, "demo-portal");
        Events.Add(login);
        return login;
    }

    private T Reach<T>(Func<T> action) => Unreachable ? throw new HttpRequestException("broker unreachable") : action();

    public Task<IReadOnlyList<LoginEvent>> GetLoginEventsAsync(int max, CancellationToken ct) =>
        Task.FromResult(Reach<IReadOnlyList<LoginEvent>>(() => [.. Events.OrderByDescending(e => e.Time).Take(max)]));

    public Task<KeycloakUser?> GetUserAsync(string userId, CancellationToken ct) =>
        Task.FromResult(Reach(() => Users.TryGetValue(userId, out var u) ? new KeycloakUser(u.Id, u.Username, u.Enabled, $"upstream-{u.Username}") : null));

    public Task<KeycloakUser?> FindUserByUsernameAsync(string username, CancellationToken ct) =>
        GetUserAsync(Users.Values.FirstOrDefault(u => u.Username == username)?.Id ?? "", ct);

    public Task<IReadOnlyList<string>> GetRealmRolesAsync(string userId, CancellationToken ct) =>
        Task.FromResult(Reach<IReadOnlyList<string>>(() => [.. Users[userId].Roles]));

    public Task<bool> HasPasskeyAsync(string userId, CancellationToken ct) => Task.FromResult(Reach(() => Users[userId].HasPasskey));

    public Task RequirePasskeyEnrolmentAsync(string userId, CancellationToken ct) =>
        Task.FromResult(Reach(() => Users[userId].PasskeyEnrolmentRequired = true));

    public Task<IReadOnlyList<string>> GetRoleMemberIdsAsync(string role, CancellationToken ct) =>
        Task.FromResult(Reach<IReadOnlyList<string>>(() => [.. Users.Values.Where(u => u.Roles.Contains(role)).Select(u => u.Id)]));

    public Task AddRealmRoleAsync(string userId, string role, CancellationToken ct) => Task.FromResult(Reach(() => Users[userId].Roles.Add(role)));

    public Task RemoveRealmRoleAsync(string userId, string role, CancellationToken ct) => Task.FromResult(Reach(() => Users[userId].Roles.Remove(role)));

    public Task<string?> GetBrowserFlowAsync(CancellationToken ct) => Task.FromResult(Reach<string?>(() => BrowserFlow));

    public Task SetBrowserFlowAsync(string flowAlias, CancellationToken ct) => Task.FromResult(Reach(() => BrowserFlow = flowAlias));

    public Task LogoutAllAsync(CancellationToken ct) => Task.FromResult(Reach(() => ++LogoutAllCalls));

    public Task LogoutUserAsync(string userId, CancellationToken ct)
    {
        Reach(() => true);
        LoggedOutUsers.Add(userId);
        return Task.CompletedTask;
    }
}

/// <summary>A node wired to fakes, with a controllable clock.</summary>
public sealed class TestNode
{
    public const string EligibleRole = "continuity-eligible";

    public TestClock Clock { get; } = new(new DateTimeOffset(2026, 11, 16, 9, 0, 0, TimeSpan.Zero));
    public FakeKeycloak Keycloak { get; } = new();
    public InMemoryMifStore Store { get; } = new();
    public MifOptions Options { get; } = new() { Continuity = { FailureThreshold = 2, RecoveryThreshold = 2 }, Snapshot = { TtlHours = 72 } };
    public SnapshotSigner Signer { get; }
    public AuditLog Audit { get; }
    public ContinuityCoordinator Continuity { get; }
    public SnapshotService Snapshots { get; }

    public TestNode()
    {
        var options = Microsoft.Extensions.Options.Options.Create(Options);
        Signer = new SnapshotSigner(ECDsa.Create(ECCurve.NamedCurves.nistP256), [], Options.Snapshot.Issuer);
        Audit = new AuditLog(Store, Clock, NullLogger<AuditLog>.Instance);
        Continuity = new ContinuityCoordinator(Keycloak, Store, Audit, options, Clock);
        Snapshots = new SnapshotService(Keycloak, Store, Signer, Audit, Continuity, options, Clock, NullLogger<SnapshotService>.Instance);
    }

    public async Task TickAsync()
    {
        await Snapshots.ProcessLoginEventsAsync(default);
        await Snapshots.ReconcileEligibilityAsync(default);
    }

    public async Task<IReadOnlyList<string>> AuditTypesAsync() => [.. (await Store.GetAuditAsync(1000, default)).Select(r => r.Type)];

    public async Task EnterDegradedAsync()
    {
        for (var i = 0; i < Options.Continuity.FailureThreshold; i++) await Continuity.ObserveAsync(new ProbeResult(false, "down"), default);
    }
}
