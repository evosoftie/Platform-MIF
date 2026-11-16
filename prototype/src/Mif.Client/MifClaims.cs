using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;

namespace Mif.Client;

/// <summary>Claims of the MIF v0 token profile (see docs/profiles/private-mesh.md).</summary>
public static class MifClaimTypes
{
    /// <summary>
    /// Alias of the upstream identity provider that verified this sign-in session live.
    /// Absent when the session was established in continuity mode (passkey + identity snapshot).
    /// </summary>
    public const string UpstreamIdp = "mif_idp";

    public const string Roles = "roles";
    public const string Username = "preferred_username";
}

public static class MifPrincipalExtensions
{
    /// <summary>The upstream IdP that verified this session live, or null for a continuity session.</summary>
    public static string? UpstreamIdp(this ClaimsPrincipal user)
    {
        var value = user.FindFirst(MifClaimTypes.UpstreamIdp)?.Value;
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }

    /// <summary>
    /// True when the session was NOT verified live by an upstream IdP. This fails closed: a token
    /// that is missing the marker claim for any reason is treated as a continuity session.
    /// </summary>
    public static bool IsContinuitySession(this ClaimsPrincipal user) =>
        user.Identity?.IsAuthenticated == true && user.UpstreamIdp() is null;
}

public static class MifPolicies
{
    /// <summary>Requires a session verified live by an upstream IdP. Use it on high-risk operations.</summary>
    public const string LiveIdentity = "Mif.LiveIdentity";

    public static AuthorizationBuilder AddMifPolicies(this AuthorizationBuilder builder) =>
        builder.AddPolicy(LiveIdentity, policy => policy
            .RequireAuthenticatedUser()
            .RequireAssertion(context => !context.User.IsContinuitySession()));
}
