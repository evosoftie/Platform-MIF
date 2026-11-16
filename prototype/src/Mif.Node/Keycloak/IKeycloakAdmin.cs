namespace Mif.Node.Keycloak;

/// <summary>A successful sign-in recorded by the broker realm.</summary>
/// <param name="IdentityProvider">Upstream IdP alias when the sign-in was brokered live; null for passkey or SSO-cookie sign-ins.</param>
public sealed record LoginEvent(string Id, DateTimeOffset Time, string UserId, string? IdentityProvider, string? ClientId);

public sealed record KeycloakUser(string Id, string Username, bool Enabled, string? UpstreamSubject);

/// <summary>The subset of the Keycloak admin API that the node depends on.</summary>
public interface IKeycloakAdmin
{
    Task<IReadOnlyList<LoginEvent>> GetLoginEventsAsync(int max, CancellationToken ct);
    Task<KeycloakUser?> GetUserAsync(string userId, CancellationToken ct);
    Task<KeycloakUser?> FindUserByUsernameAsync(string username, CancellationToken ct);
    Task<IReadOnlyList<string>> GetRealmRolesAsync(string userId, CancellationToken ct);
    Task<bool> HasPasskeyAsync(string userId, CancellationToken ct);
    Task RequirePasskeyEnrolmentAsync(string userId, CancellationToken ct);

    Task<IReadOnlyList<string>> GetRoleMemberIdsAsync(string role, CancellationToken ct);
    Task AddRealmRoleAsync(string userId, string role, CancellationToken ct);
    Task RemoveRealmRoleAsync(string userId, string role, CancellationToken ct);

    Task<string?> GetBrowserFlowAsync(CancellationToken ct);
    Task SetBrowserFlowAsync(string flowAlias, CancellationToken ct);
    Task LogoutAllAsync(CancellationToken ct);
    Task LogoutUserAsync(string userId, CancellationToken ct);
}
