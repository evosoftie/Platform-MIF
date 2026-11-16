using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using Mif.Node;
using Mif.Node.Audit;
using Mif.Node.Continuity;
using Mif.Node.Keycloak;
using Mif.Node.Snapshots;
using Mif.Node.Storage;
using Npgsql;

var builder = WebApplication.CreateBuilder(args);
builder.Services.Configure<MifOptions>(builder.Configuration.GetSection("Mif"));
var settings = builder.Configuration.GetSection("Mif").Get<MifOptions>() ?? new MifOptions();

builder.WebHost.ConfigureKestrel(kestrel =>
{
    kestrel.ListenAnyIP(settings.PublicPort);
    kestrel.ListenAnyIP(settings.OperatorPort);
});
builder.Services.ConfigureHttpJsonOptions(json => json.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));

builder.Services.AddSingleton(TimeProvider.System);
if (string.IsNullOrWhiteSpace(settings.Database))
{
    builder.Services.AddSingleton<IMifStore, InMemoryMifStore>();
}
else
{
    builder.Services.AddSingleton(NpgsqlDataSource.Create(settings.Database));
    builder.Services.AddSingleton<IMifStore, PostgresMifStore>();
}
builder.Services.AddSingleton<AuditLog>();
builder.Services.AddSingleton(services => SnapshotSigner.LoadOrCreate(
    settings.Snapshot.KeyDirectory, settings.Snapshot.Issuer, services.GetRequiredService<ILoggerFactory>().CreateLogger<SnapshotSigner>()));
builder.Services.AddSingleton<IKeycloakAdmin>(services => new KeycloakAdminClient(
    LongLivedHttpClient(), services.GetRequiredService<IOptions<MifOptions>>(), services.GetRequiredService<TimeProvider>()));
builder.Services.AddSingleton<IUpstreamProbe>(services => new OidcUpstreamProbe(
    LongLivedHttpClient(), services.GetRequiredService<IOptions<MifOptions>>()));
builder.Services.AddSingleton<ContinuityCoordinator>();
builder.Services.AddSingleton<SnapshotService>();
builder.Services.AddSingleton<NodeWorker>();
builder.Services.AddHostedService(services => services.GetRequiredService<NodeWorker>());

var app = builder.Build();

// ---- Public endpoints: read-only, safe for applications and peer nodes on the mesh ----

app.MapGet("/healthz", (NodeWorker worker) => worker.Ready ? Results.Ok(new { status = "ok" }) : Results.StatusCode(503));

app.MapGet("/status", (ContinuityCoordinator continuity, SnapshotSigner signer, IOptions<MifOptions> options) => new
{
    issuer = options.Value.Snapshot.Issuer,
    continuity = continuity.Status,
    snapshot = new { ttl_hours = options.Value.Snapshot.TtlHours, signing_key = signer.KeyId },
});

app.MapGet("/.well-known/mif/jwks.json", (SnapshotSigner signer) => signer.Jwks());

app.MapPost("/snapshots/verify", async (VerifyRequest request, SnapshotService snapshots, CancellationToken ct) =>
    await snapshots.VerifyAsync(request.Snapshot, ct));

// ---- Operator endpoints: only served on the operator port, which should be bound to loopback ----

var operatorApi = app.MapGroup("/operator").AddEndpointFilter(async (context, next) =>
    context.HttpContext.Connection.LocalPort == settings.OperatorPort ? await next(context) : Results.NotFound());

operatorApi.MapPost("/mode", async (ModeRequest request, ContinuityCoordinator continuity, CancellationToken ct) =>
    string.IsNullOrWhiteSpace(request.Reason)
        ? Results.BadRequest(new { error = "reason is required" })
        : Results.Ok(await continuity.SetOverrideAsync(request.Override, request.Reason, ct)));

operatorApi.MapPost("/revoke", async (RevokeRequest request, SnapshotService snapshots, CancellationToken ct) =>
    string.IsNullOrWhiteSpace(request.Reason)
        ? Results.BadRequest(new { error = "reason is required" })
        : await snapshots.RevokeAsync(request.Username, request.Reason, ct)
            ? Results.Ok(new { revoked = request.Username })
            : Results.NotFound(new { error = $"no user '{request.Username}'" }));

operatorApi.MapGet("/snapshots", async (IMifStore store, TimeProvider time, CancellationToken ct) =>
    (await store.GetCurrentSnapshotsAsync(ct)).OrderBy(s => s.Username).Select(s => new
    {
        s.Username,
        s.Jti,
        s.VerifiedAt,
        s.ExpiresAt,
        s.RevokedAt,
        s.RevokedReason,
        valid = s.RevokedAt is null && s.ExpiresAt > time.GetUtcNow(),
        s.Jws,
    }));

operatorApi.MapGet("/audit", async (IMifStore store, CancellationToken ct, int max = 100) =>
{
    var records = await store.GetAuditAsync(Math.Clamp(max, 1, 5000), ct);
    return new { chain_intact = AuditLog.VerifyChain(records), records };
});

app.Run();

// The node's clients live as long as the process, so recycle connections to pick up DNS changes (for example a failover).
static HttpClient LongLivedHttpClient() =>
    new(new SocketsHttpHandler { PooledConnectionLifetime = TimeSpan.FromMinutes(2) }) { Timeout = TimeSpan.FromSeconds(10) };

internal sealed record VerifyRequest(string Snapshot);
internal sealed record ModeRequest(ModeOverride Override, string Reason);
internal sealed record RevokeRequest(string Username, string Reason);
