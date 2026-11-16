using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Options;

namespace Mif.Node.Keycloak;

public sealed class KeycloakAdminClient(HttpClient http, IOptions<MifOptions> options, TimeProvider time) : IKeycloakAdmin
{
    private const string PasskeyCredentialType = "webauthn-passwordless";
    private const string PasskeyRequiredAction = "webauthn-register-passwordless";

    private readonly KeycloakOptions _kc = options.Value.Keycloak;
    private readonly SemaphoreSlim _tokenLock = new(1, 1);
    private readonly ConcurrentDictionary<string, JsonNode> _roleCache = new();
    private string? _token;
    private DateTimeOffset _tokenExpires;

    private string Admin(string path) => $"{_kc.BaseUrl.TrimEnd('/')}/admin/realms/{_kc.Realm}{path}";

    public async Task<IReadOnlyList<LoginEvent>> GetLoginEventsAsync(int max, CancellationToken ct)
    {
        var events = await GetAsync($"/events?type=LOGIN&first=0&max={max}", ct) as JsonArray ?? [];
        var result = new List<LoginEvent>(events.Count);
        foreach (var e in events)
        {
            var id = e?["id"]?.GetValue<string>();
            var userId = e?["userId"]?.GetValue<string>();
            if (id is null || userId is null) continue;
            result.Add(new LoginEvent(
                id,
                DateTimeOffset.FromUnixTimeMilliseconds(e!["time"]!.GetValue<long>()),
                userId,
                e["details"]?["identity_provider"]?.GetValue<string>(),
                e["clientId"]?.GetValue<string>()));
        }
        return result;
    }

    public async Task<KeycloakUser?> GetUserAsync(string userId, CancellationToken ct)
    {
        var user = await GetAsync($"/users/{Uri.EscapeDataString(userId)}", ct, allowNotFound: true);
        return user is null ? null : ToUser(user);
    }

    public async Task<KeycloakUser?> FindUserByUsernameAsync(string username, CancellationToken ct)
    {
        var users = await GetAsync($"/users?exact=true&username={Uri.EscapeDataString(username)}", ct) as JsonArray;
        var id = users?.FirstOrDefault()?["id"]?.GetValue<string>();
        return id is null ? null : await GetUserAsync(id, ct); // the search result omits federated identities
    }

    private KeycloakUser ToUser(JsonNode user)
    {
        var upstream = (user["federatedIdentities"] as JsonArray)?
            .FirstOrDefault(f => f?["identityProvider"]?.GetValue<string>() == options.Value.Upstream.Alias);
        return new KeycloakUser(
            user["id"]!.GetValue<string>(),
            user["username"]!.GetValue<string>(),
            user["enabled"]?.GetValue<bool>() ?? false,
            upstream?["userId"]?.GetValue<string>());
    }

    public async Task<IReadOnlyList<string>> GetRealmRolesAsync(string userId, CancellationToken ct)
    {
        var roles = await GetAsync($"/users/{userId}/role-mappings/realm", ct) as JsonArray ?? [];
        return [.. roles.Select(r => r!["name"]!.GetValue<string>())];
    }

    public async Task<bool> HasPasskeyAsync(string userId, CancellationToken ct)
    {
        var credentials = await GetAsync($"/users/{userId}/credentials", ct) as JsonArray ?? [];
        return credentials.Any(c => c?["type"]?.GetValue<string>() == PasskeyCredentialType);
    }

    public async Task RequirePasskeyEnrolmentAsync(string userId, CancellationToken ct)
    {
        // Keycloak replaces the whole user on PUT, so read, modify and write back the full representation.
        var user = await GetAsync($"/users/{userId}", ct) as JsonObject ?? throw new InvalidOperationException($"User {userId} not found");
        var actions = user["requiredActions"] as JsonArray ?? [];
        if (actions.Any(a => a?.GetValue<string>() == PasskeyRequiredAction)) return;
        actions.Add(PasskeyRequiredAction);
        user["requiredActions"] = actions.DeepClone();
        await SendAsync(HttpMethod.Put, $"/users/{userId}", user, ct);
    }

    public async Task<IReadOnlyList<string>> GetRoleMemberIdsAsync(string role, CancellationToken ct)
    {
        const int page = 200;
        var ids = new List<string>();
        for (var first = 0; ; first += page)
        {
            var users = await GetAsync($"/roles/{Uri.EscapeDataString(role)}/users?first={first}&max={page}", ct) as JsonArray ?? [];
            ids.AddRange(users.Select(u => u!["id"]!.GetValue<string>()));
            if (users.Count < page) return ids;
        }
    }

    public async Task AddRealmRoleAsync(string userId, string role, CancellationToken ct) =>
        await SendAsync(HttpMethod.Post, $"/users/{userId}/role-mappings/realm", new JsonArray((await RoleAsync(role, ct)).DeepClone()), ct);

    public async Task RemoveRealmRoleAsync(string userId, string role, CancellationToken ct) =>
        await SendAsync(HttpMethod.Delete, $"/users/{userId}/role-mappings/realm", new JsonArray((await RoleAsync(role, ct)).DeepClone()), ct);

    private async Task<JsonNode> RoleAsync(string role, CancellationToken ct)
    {
        if (_roleCache.TryGetValue(role, out var cached)) return cached;
        var node = await GetAsync($"/roles/{Uri.EscapeDataString(role)}", ct) ?? throw new InvalidOperationException($"Realm role '{role}' does not exist");
        return _roleCache[role] = node;
    }

    public async Task<string?> GetBrowserFlowAsync(CancellationToken ct) =>
        (await GetAsync("", ct))?["browserFlow"]?.GetValue<string>();

    public Task SetBrowserFlowAsync(string flowAlias, CancellationToken ct) =>
        SendAsync(HttpMethod.Put, "", new JsonObject { ["browserFlow"] = flowAlias }, ct);

    public Task LogoutAllAsync(CancellationToken ct) => SendAsync(HttpMethod.Post, "/logout-all", null, ct);

    public Task LogoutUserAsync(string userId, CancellationToken ct) => SendAsync(HttpMethod.Post, $"/users/{userId}/logout", null, ct);

    private async Task<JsonNode?> GetAsync(string path, CancellationToken ct, bool allowNotFound = false)
    {
        using var response = await SendWithTokenAsync(HttpMethod.Get, path, null, ct);
        if (allowNotFound && response.StatusCode == HttpStatusCode.NotFound) return null;
        await EnsureSuccessAsync(response, ct);
        return await response.Content.ReadFromJsonAsync<JsonNode>(ct);
    }

    private async Task SendAsync(HttpMethod method, string path, JsonNode? body, CancellationToken ct)
    {
        using var response = await SendWithTokenAsync(method, path, body, ct);
        await EnsureSuccessAsync(response, ct);
    }

    /// <summary>
    /// Sends with the cached service-account token and, if the broker rejects it, once more with a
    /// fresh one. Ending all sessions (which the node itself does at recovery) invalidates every
    /// token issued before that moment, the node's own included.
    /// </summary>
    private async Task<HttpResponseMessage> SendWithTokenAsync(HttpMethod method, string path, JsonNode? body, CancellationToken ct)
    {
        for (var attempt = 1; ; attempt++)
        {
            using var request = new HttpRequestMessage(method, Admin(path));
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await TokenAsync(ct));
            if (body is not null) request.Content = JsonContent.Create(body);
            var response = await http.SendAsync(request, ct);
            if (response.StatusCode != HttpStatusCode.Unauthorized || attempt == 2) return response;
            response.Dispose();
            _token = null;
        }
    }

    private static async Task EnsureSuccessAsync(HttpResponseMessage response, CancellationToken ct)
    {
        if (response.IsSuccessStatusCode) return;
        var body = await response.Content.ReadAsStringAsync(ct);
        throw new HttpRequestException(
            $"Keycloak {response.RequestMessage?.Method} {response.RequestMessage?.RequestUri?.AbsolutePath} returned {(int)response.StatusCode}: {body}",
            null, response.StatusCode);
    }

    private async Task<string> TokenAsync(CancellationToken ct)
    {
        if (_token is not null && time.GetUtcNow() < _tokenExpires) return _token;
        await _tokenLock.WaitAsync(ct);
        try
        {
            if (_token is not null && time.GetUtcNow() < _tokenExpires) return _token;
            using var response = await http.PostAsync(
                $"{_kc.BaseUrl.TrimEnd('/')}/realms/{_kc.Realm}/protocol/openid-connect/token",
                new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["grant_type"] = "client_credentials",
                    ["client_id"] = _kc.ClientId,
                    ["client_secret"] = _kc.ClientSecret,
                }), ct);
            await EnsureSuccessAsync(response, ct);
            using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
            _token = json.RootElement.GetProperty("access_token").GetString()!;
            _tokenExpires = time.GetUtcNow().AddSeconds(Math.Max(5, json.RootElement.GetProperty("expires_in").GetInt32() - 30));
            return _token;
        }
        finally
        {
            _tokenLock.Release();
        }
    }
}
