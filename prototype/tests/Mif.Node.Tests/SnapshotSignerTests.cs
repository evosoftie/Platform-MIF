using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Mif.Node.Snapshots;

namespace Mif.Node.Tests;

public class SnapshotSignerTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 16, 9, 0, 0, TimeSpan.Zero);

    private static SnapshotClaims Claims(TimeSpan? ttl = null) => new(
        "jti-1", "user-1", "alice", "entra", "upstream-1", Now, Now + (ttl ?? TimeSpan.FromHours(72)), "AAL1", ["finance-approver"]);

    private static ECDsa NewKey() => ECDsa.Create(ECCurve.NamedCurves.nistP256);

    [Fact]
    public void A_signed_snapshot_verifies_and_carries_its_claims()
    {
        var signer = new SnapshotSigner(NewKey(), [], "mif-node");

        var result = signer.Validate(signer.Sign(Claims(), Now), Now.AddHours(1));

        Assert.True(result.Valid, result.Error);
        Assert.Equal("user-1", result.Token!.Subject);
        Assert.Equal("jti-1", result.Token.Id);
        Assert.Equal("entra", result.Token.GetClaim("source_idp").Value);
        Assert.Equal(["finance-approver"], result.Token.Claims.Where(c => c.Type == "roles").Select(c => c.Value));
    }

    [Fact]
    public void A_snapshot_is_rejected_from_the_moment_it_expires()
    {
        var signer = new SnapshotSigner(NewKey(), [], "mif-node");
        var jws = signer.Sign(Claims(TimeSpan.FromHours(72)), Now);

        Assert.True(signer.Validate(jws, Now.AddHours(72).AddSeconds(-1)).Valid);
        Assert.Equal("expired", signer.Validate(jws, Now.AddHours(72)).Error);
    }

    [Fact]
    public void A_snapshot_with_an_altered_payload_is_rejected()
    {
        var signer = new SnapshotSigner(NewKey(), [], "mif-node");
        var parts = signer.Sign(Claims(), Now).Split('.');
        var payload = Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(parts[1])).Replace("finance-approver", "global-admin");
        var forged = $"{parts[0]}.{Base64UrlEncoder.Encode(payload)}.{parts[2]}";

        Assert.False(signer.Validate(forged, Now).Valid);
    }

    [Fact]
    public void A_snapshot_signed_by_an_unknown_key_is_rejected()
    {
        var stranger = new SnapshotSigner(NewKey(), [], "mif-node");
        var signer = new SnapshotSigner(NewKey(), [], "mif-node");

        Assert.False(signer.Validate(stranger.Sign(Claims(), Now), Now).Valid);
    }

    [Fact]
    public void A_snapshot_signed_by_a_trusted_peer_node_is_accepted()
    {
        var peerKey = NewKey();
        var peer = new SnapshotSigner(peerKey, [], "mif-node");
        var publicOnly = ECDsa.Create(peerKey.ExportParameters(includePrivateParameters: false));
        var standby = new SnapshotSigner(NewKey(), [publicOnly], "mif-node");

        Assert.True(standby.Validate(peer.Sign(Claims(), Now), Now).Valid);
    }

    [Fact]
    public void An_ordinary_token_from_the_same_key_is_not_a_snapshot()
    {
        var key = new ECDsaSecurityKey(NewKey());
        var signer = new SnapshotSigner(key.ECDsa, [], "mif-node");
        var accessToken = new Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "mif-node",
            Expires = Now.AddHours(1).UtcDateTime,
            IssuedAt = Now.UtcDateTime,
            NotBefore = Now.UtcDateTime,
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256),
        });

        Assert.False(signer.Validate(accessToken, Now).Valid);
    }

    [Fact]
    public void The_key_is_created_once_and_reloaded_from_disk()
    {
        var directory = Directory.CreateTempSubdirectory("mif-keys").FullName;
        try
        {
            var first = SnapshotSigner.LoadOrCreate(directory, "mif-node", Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);
            var second = SnapshotSigner.LoadOrCreate(directory, "mif-node", Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);

            Assert.Equal(first.KeyId, second.KeyId);
            Assert.True(second.Validate(first.Sign(Claims(), Now), Now).Valid);
            Assert.True(File.Exists(Path.Combine(directory, "signing-key.pub.pem")));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
