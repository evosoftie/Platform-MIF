using System.Security.Cryptography;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Mif.Node.Snapshots;

/// <summary>What a snapshot asserts: who was verified, by whom, when, and with which roles.</summary>
public sealed record SnapshotClaims(
    string Jti,
    string Subject,
    string Username,
    string UpstreamIdp,
    string? UpstreamSubject,
    DateTimeOffset VerifiedAt,
    DateTimeOffset ExpiresAt,
    string Assurance,
    IReadOnlyList<string> Roles);

public sealed record SnapshotValidation(bool Valid, string? Error, JsonWebToken? Token)
{
    public static SnapshotValidation Fail(string error) => new(false, error, null);
}

/// <summary>Signs and verifies identity snapshots as compact JWS (ES256). Verification needs no network access.</summary>
public sealed class SnapshotSigner
{
    public const string TokenType = "mif-snapshot+jwt";
    private const string SigningKeyFile = "signing-key.pem";

    private readonly JsonWebTokenHandler _handler = new() { SetDefaultTimesOnTokenCreation = false };
    private readonly ECDsaSecurityKey _signingKey;
    private readonly List<ECDsaSecurityKey> _trusted;
    private readonly string _issuer;

    public SnapshotSigner(ECDsa signingKey, IEnumerable<ECDsa> trustedPeerKeys, string issuer)
    {
        _issuer = issuer;
        _signingKey = WithKeyId(signingKey);
        _trusted = [_signingKey, .. trustedPeerKeys.Select(WithKeyId)];
    }

    public string KeyId => _signingKey.KeyId;

    /// <summary>
    /// Loads the node's signing key, creating it on first start, plus the public keys of peer nodes
    /// from the "trusted" sub-directory. The key lives on local disk on purpose: a vault that needs
    /// an Entra token to open would be unavailable in exactly the outage this node exists for.
    /// </summary>
    public static SnapshotSigner LoadOrCreate(string keyDirectory, string issuer, ILogger logger)
    {
        Directory.CreateDirectory(keyDirectory);
        var keyPath = Path.Combine(keyDirectory, SigningKeyFile);
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        if (File.Exists(keyPath))
        {
            key.ImportFromPem(File.ReadAllText(keyPath));
        }
        else
        {
            File.WriteAllText(keyPath, key.ExportPkcs8PrivateKeyPem());
            if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            File.WriteAllText(Path.ChangeExtension(keyPath, ".pub.pem"), key.ExportSubjectPublicKeyInfoPem());
            logger.LogWarning("Created a new snapshot signing key at {Path}. Copy the .pub.pem file to the peer node's trusted directory.", keyPath);
        }

        var trusted = new List<ECDsa>();
        var trustedDirectory = Path.Combine(keyDirectory, "trusted");
        if (Directory.Exists(trustedDirectory))
        {
            foreach (var file in Directory.EnumerateFiles(trustedDirectory, "*.pem"))
            {
                var peer = ECDsa.Create();
                peer.ImportFromPem(File.ReadAllText(file));
                trusted.Add(peer);
            }
        }

        return new SnapshotSigner(key, trusted, issuer);
    }

    public string Sign(SnapshotClaims claims, DateTimeOffset issuedAt)
    {
        var payload = new Dictionary<string, object>
        {
            ["jti"] = claims.Jti,
            ["sub"] = claims.Subject,
            ["preferred_username"] = claims.Username,
            ["verified_at"] = claims.VerifiedAt.ToUnixTimeSeconds(),
            ["source_idp"] = claims.UpstreamIdp,
            ["assurance"] = claims.Assurance,
            ["roles"] = claims.Roles.ToArray(),
        };
        if (claims.UpstreamSubject is not null) payload["source_sub"] = claims.UpstreamSubject;

        return _handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = _issuer,
            IssuedAt = issuedAt.UtcDateTime,
            Expires = claims.ExpiresAt.UtcDateTime,
            TokenType = TokenType,
            SigningCredentials = new SigningCredentials(_signingKey, SecurityAlgorithms.EcdsaSha256),
            Claims = payload,
        });
    }

    /// <summary>Checks signature, type, issuer and expiry. Revocation is the caller's concern.</summary>
    public SnapshotValidation Validate(string jws, DateTimeOffset now)
    {
        var result = _handler.ValidateTokenAsync(jws, new TokenValidationParameters
        {
            ValidIssuer = _issuer,
            ValidateAudience = false,
            ValidateLifetime = false, // checked below against the injected clock, with no skew allowance
            ValidTypes = [TokenType],
            ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256],
            IssuerSigningKeys = _trusted,
        }).GetAwaiter().GetResult();

        if (!result.IsValid) return SnapshotValidation.Fail(result.Exception?.GetType().Name ?? "invalid");
        var token = (JsonWebToken)result.SecurityToken;
        if (token.ValidTo == DateTime.MinValue) return SnapshotValidation.Fail("no_expiry");
        if (token.ValidTo <= now.UtcDateTime) return SnapshotValidation.Fail("expired");
        return new SnapshotValidation(true, null, token);
    }

    /// <summary>Public keys of this node and its trusted peers, as a JWK set.</summary>
    public object Jwks() => new
    {
        keys = _trusted.Select(k =>
        {
            var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(k);
            return new { kty = jwk.Kty, crv = jwk.Crv, x = jwk.X, y = jwk.Y, kid = k.KeyId, use = "sig", alg = SecurityAlgorithms.EcdsaSha256 };
        }),
    };

    private static ECDsaSecurityKey WithKeyId(ECDsa key)
    {
        var securityKey = new ECDsaSecurityKey(key);
        var publicJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(ECDsa.Create(key.ExportParameters(false))));
        securityKey.KeyId = Base64UrlEncoder.Encode(publicJwk.ComputeJwkThumbprint());
        return securityKey;
    }
}
