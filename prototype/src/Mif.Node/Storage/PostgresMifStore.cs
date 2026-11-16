using Npgsql;

namespace Mif.Node.Storage;

/// <summary>
/// Keeps node state in a "mif" schema next to the broker's own tables, so one replication stream
/// carries everything the standby node needs.
/// </summary>
public sealed class PostgresMifStore(NpgsqlDataSource db) : IMifStore
{
    private const string Schema = """
        CREATE SCHEMA IF NOT EXISTS mif;
        CREATE TABLE IF NOT EXISTS mif.snapshots (
            jti            text PRIMARY KEY,
            user_id        text NOT NULL,
            username       text NOT NULL,
            verified_at    timestamptz NOT NULL,
            expires_at     timestamptz NOT NULL,
            jws            text NOT NULL,
            revoked_at     timestamptz NULL,
            revoked_reason text NULL
        );
        CREATE INDEX IF NOT EXISTS snapshots_user ON mif.snapshots (user_id, verified_at DESC);
        CREATE TABLE IF NOT EXISTS mif.processed_events (id text PRIMARY KEY, at timestamptz NOT NULL);
        CREATE TABLE IF NOT EXISTS mif.state (key text PRIMARY KEY, value text NOT NULL);
        CREATE TABLE IF NOT EXISTS mif.audit (
            seq       bigserial PRIMARY KEY,
            at        timestamptz NOT NULL,
            type      text NOT NULL,
            subject   text NULL,
            data      text NOT NULL,
            prev_hash text NOT NULL,
            hash      text NOT NULL
        );
        """;

    private const string SnapshotColumns = "jti, user_id, username, verified_at, expires_at, jws, revoked_at, revoked_reason";
    private const string AuditColumns = "seq, at, type, subject, data, prev_hash, hash";

    public async Task InitializeAsync(CancellationToken ct)
    {
        await using var cmd = db.CreateCommand(Schema);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<bool> TryMarkEventProcessedAsync(string eventId, DateTimeOffset at, CancellationToken ct)
    {
        await using var cmd = db.CreateCommand("INSERT INTO mif.processed_events (id, at) VALUES ($1, $2) ON CONFLICT DO NOTHING");
        cmd.Parameters.AddWithValue(eventId);
        cmd.Parameters.AddWithValue(at.ToUniversalTime());
        return await cmd.ExecuteNonQueryAsync(ct) == 1;
    }

    public async Task SaveSnapshotAsync(SnapshotRecord s, CancellationToken ct)
    {
        await using var cmd = db.CreateCommand(
            "INSERT INTO mif.snapshots (jti, user_id, username, verified_at, expires_at, jws) VALUES ($1, $2, $3, $4, $5, $6)");
        cmd.Parameters.AddWithValue(s.Jti);
        cmd.Parameters.AddWithValue(s.UserId);
        cmd.Parameters.AddWithValue(s.Username);
        cmd.Parameters.AddWithValue(s.VerifiedAt.ToUniversalTime());
        cmd.Parameters.AddWithValue(s.ExpiresAt.ToUniversalTime());
        cmd.Parameters.AddWithValue(s.Jws);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<IReadOnlyList<SnapshotRecord>> GetCurrentSnapshotsAsync(CancellationToken ct)
    {
        await using var cmd = db.CreateCommand(
            $"SELECT DISTINCT ON (user_id) {SnapshotColumns} FROM mif.snapshots ORDER BY user_id, verified_at DESC");
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        var result = new List<SnapshotRecord>();
        while (await reader.ReadAsync(ct)) result.Add(ReadSnapshot(reader));
        return result;
    }

    public async Task<SnapshotRecord?> GetSnapshotAsync(string jti, CancellationToken ct)
    {
        await using var cmd = db.CreateCommand($"SELECT {SnapshotColumns} FROM mif.snapshots WHERE jti = $1");
        cmd.Parameters.AddWithValue(jti);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct) ? ReadSnapshot(reader) : null;
    }

    public async Task<int> RevokeUserSnapshotsAsync(string userId, DateTimeOffset at, string reason, CancellationToken ct)
    {
        await using var cmd = db.CreateCommand(
            "UPDATE mif.snapshots SET revoked_at = $2, revoked_reason = $3 WHERE user_id = $1 AND revoked_at IS NULL");
        cmd.Parameters.AddWithValue(userId);
        cmd.Parameters.AddWithValue(at.ToUniversalTime());
        cmd.Parameters.AddWithValue(reason);
        return await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<string?> GetStateAsync(string key, CancellationToken ct)
    {
        await using var cmd = db.CreateCommand("SELECT value FROM mif.state WHERE key = $1");
        cmd.Parameters.AddWithValue(key);
        return await cmd.ExecuteScalarAsync(ct) as string;
    }

    public async Task SetStateAsync(string key, string value, CancellationToken ct)
    {
        await using var cmd = db.CreateCommand(
            "INSERT INTO mif.state (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value");
        cmd.Parameters.AddWithValue(key);
        cmd.Parameters.AddWithValue(value);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<AuditRecord?> GetLastAuditAsync(CancellationToken ct)
    {
        await using var cmd = db.CreateCommand($"SELECT {AuditColumns} FROM mif.audit ORDER BY seq DESC LIMIT 1");
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct) ? ReadAudit(reader) : null;
    }

    public async Task AppendAuditAsync(AuditRecord r, CancellationToken ct)
    {
        await using var cmd = db.CreateCommand(
            "INSERT INTO mif.audit (at, type, subject, data, prev_hash, hash) VALUES ($1, $2, $3, $4, $5, $6)");
        cmd.Parameters.AddWithValue(r.At.ToUniversalTime());
        cmd.Parameters.AddWithValue(r.Type);
        cmd.Parameters.AddWithValue((object?)r.Subject ?? DBNull.Value);
        cmd.Parameters.AddWithValue(r.Data);
        cmd.Parameters.AddWithValue(r.PrevHash);
        cmd.Parameters.AddWithValue(r.Hash);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<IReadOnlyList<AuditRecord>> GetAuditAsync(int max, CancellationToken ct)
    {
        await using var cmd = db.CreateCommand(
            $"SELECT {AuditColumns} FROM (SELECT {AuditColumns} FROM mif.audit ORDER BY seq DESC LIMIT $1) newest ORDER BY seq");
        cmd.Parameters.AddWithValue(max);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        var result = new List<AuditRecord>();
        while (await reader.ReadAsync(ct)) result.Add(ReadAudit(reader));
        return result;
    }

    private static SnapshotRecord ReadSnapshot(NpgsqlDataReader r) => new(
        r.GetString(0), r.GetString(1), r.GetString(2),
        r.GetFieldValue<DateTimeOffset>(3), r.GetFieldValue<DateTimeOffset>(4), r.GetString(5),
        r.IsDBNull(6) ? null : r.GetFieldValue<DateTimeOffset>(6),
        r.IsDBNull(7) ? null : r.GetString(7));

    private static AuditRecord ReadAudit(NpgsqlDataReader r) => new(
        r.GetInt64(0), r.GetFieldValue<DateTimeOffset>(1), r.GetString(2),
        r.IsDBNull(3) ? null : r.GetString(3), r.GetString(4), r.GetString(5), r.GetString(6));
}
