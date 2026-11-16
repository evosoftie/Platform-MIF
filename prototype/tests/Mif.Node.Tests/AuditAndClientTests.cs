using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Mif.Client;
using Mif.Node.Audit;

namespace Mif.Node.Tests;

public class AuditLogTests
{
    [Fact]
    public async Task Records_are_chained_and_an_untouched_log_verifies()
    {
        var node = new TestNode();
        for (var i = 0; i < 5; i++) await node.Audit.WriteAsync("test.event", "alice", new { i }, default);

        var records = await node.Store.GetAuditAsync(100, default);

        Assert.Equal(AuditLog.Genesis, records[0].PrevHash);
        Assert.True(AuditLog.VerifyChain(records));
        Assert.True(AuditLog.VerifyChain([.. records.TakeLast(2)])); // a window of the log verifies on its own
    }

    [Fact]
    public async Task Editing_a_record_breaks_the_chain()
    {
        var node = new TestNode();
        for (var i = 0; i < 5; i++) await node.Audit.WriteAsync("test.event", "alice", new { i }, default);

        node.Store.TamperWithAudit(2, r => r with { Subject = "mallory" });

        Assert.False(AuditLog.VerifyChain(await node.Store.GetAuditAsync(100, default)));
    }

    [Fact]
    public async Task Deleting_a_record_breaks_the_chain()
    {
        var node = new TestNode();
        for (var i = 0; i < 5; i++) await node.Audit.WriteAsync("test.event", "alice", new { i }, default);
        var records = (await node.Store.GetAuditAsync(100, default)).ToList();

        records.RemoveAt(2);

        Assert.False(AuditLog.VerifyChain(records));
    }

    [Fact]
    public async Task The_chain_continues_across_a_restart()
    {
        var node = new TestNode();
        await node.Audit.WriteAsync("before.restart", null, new { }, default);

        var restarted = new AuditLog(node.Store, node.Clock, Microsoft.Extensions.Logging.Abstractions.NullLogger<AuditLog>.Instance);
        await restarted.WriteAsync("after.restart", null, new { }, default);

        Assert.True(AuditLog.VerifyChain(await node.Store.GetAuditAsync(100, default)));
    }
}

public class MifClientTests
{
    private static ClaimsPrincipal User(params (string Type, string Value)[] claims) =>
        new(new ClaimsIdentity(claims.Select(c => new Claim(c.Type, c.Value)), authenticationType: "test"));

    private static async Task<bool> AllowedAsync(ClaimsPrincipal user)
    {
        var services = new ServiceCollection().AddLogging();
        services.AddAuthorizationBuilder().AddMifPolicies();
        var authorization = services.BuildServiceProvider().GetRequiredService<IAuthorizationService>();
        return (await authorization.AuthorizeAsync(user, MifPolicies.LiveIdentity)).Succeeded;
    }

    [Fact]
    public async Task A_session_verified_by_the_upstream_is_live()
    {
        var user = User(("sub", "1"), (MifClaimTypes.UpstreamIdp, "entra"));

        Assert.False(user.IsContinuitySession());
        Assert.True(await AllowedAsync(user));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    public async Task A_session_without_the_upstream_marker_is_treated_as_continuity(string? marker)
    {
        var user = marker is null ? User(("sub", "1")) : User(("sub", "1"), (MifClaimTypes.UpstreamIdp, marker));

        Assert.True(user.IsContinuitySession());
        Assert.False(await AllowedAsync(user));
    }

    [Fact]
    public async Task An_anonymous_user_is_neither_live_nor_a_continuity_session()
    {
        var anonymous = new ClaimsPrincipal(new ClaimsIdentity());

        Assert.False(anonymous.IsContinuitySession());
        Assert.False(await AllowedAsync(anonymous));
    }
}
