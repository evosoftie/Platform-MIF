using System.Net;
using System.Text;
using Mif.Node.Keycloak;

namespace Mif.Node.Tests;

public class KeycloakAdminClientTests
{
    /// <summary>A broker that hands out numbered tokens and accepts only the ones it has not invalidated.</summary>
    private sealed class StubBroker : HttpMessageHandler
    {
        public int TokensIssued { get; private set; }
        public int MinimumValidToken { get; set; } = 1;
        public List<string> AdminCalls { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var path = request.RequestUri!.AbsolutePath;
            if (path.EndsWith("/protocol/openid-connect/token"))
                return Json($$"""{"access_token":"token-{{++TokensIssued}}","expires_in":300}""");

            var token = int.Parse(request.Headers.Authorization!.Parameter!["token-".Length..]);
            AdminCalls.Add($"{request.Method} {path} token-{token}");
            if (token < MinimumValidToken) return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized));
            if (path.EndsWith("/logout-all"))
            {
                MinimumValidToken = TokensIssued + 1; // ending all sessions invalidates every token issued so far
                return Json("{}");
            }
            return Json("""{"browserFlow":"mif-normal"}""");
        }

        private static Task<HttpResponseMessage> Json(string body) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") });
    }

    private static KeycloakAdminClient Client(StubBroker broker) => new(
        new HttpClient(broker),
        Microsoft.Extensions.Options.Options.Create(new MifOptions { Keycloak = { BaseUrl = "http://broker", ClientSecret = "s" } }),
        new TestClock(DateTimeOffset.UnixEpoch));

    [Fact]
    public async Task The_service_account_token_is_reused_between_calls()
    {
        var broker = new StubBroker();
        var client = Client(broker);

        await client.GetBrowserFlowAsync(default);
        await client.GetBrowserFlowAsync(default);

        Assert.Equal(1, broker.TokensIssued);
    }

    [Fact]
    public async Task The_node_keeps_working_after_it_ends_all_sessions_which_invalidates_its_own_token()
    {
        var broker = new StubBroker();
        var client = Client(broker);

        await client.LogoutAllAsync(default);
        var flow = await client.GetBrowserFlowAsync(default);

        Assert.Equal("mif-normal", flow);
        Assert.Equal(2, broker.TokensIssued);
        Assert.Equal("GET /admin/realms/mif token-2", broker.AdminCalls[^1]);
    }

    [Fact]
    public async Task A_call_that_is_still_rejected_with_a_fresh_token_fails_instead_of_looping()
    {
        var broker = new StubBroker { MinimumValidToken = int.MaxValue };
        var client = Client(broker);

        var error = await Assert.ThrowsAsync<HttpRequestException>(() => client.GetBrowserFlowAsync(default));

        Assert.Equal(HttpStatusCode.Unauthorized, error.StatusCode);
        Assert.Equal(2, broker.AdminCalls.Count);
    }
}
