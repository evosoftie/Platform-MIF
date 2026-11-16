namespace Mif.Node.Storage;

/// <param name="VerifiedAt">When the upstream IdP last verified the user live. Expiry is anchored to this, not to processing time.</param>
public sealed record SnapshotRecord(
    string Jti,
    string UserId,
    string Username,
    DateTimeOffset VerifiedAt,
    DateTimeOffset ExpiresAt,
    string Jws,
    DateTimeOffset? RevokedAt = null,
    string? RevokedReason = null);

public sealed record AuditRecord(long Seq, DateTimeOffset At, string Type, string? Subject, string Data, string PrevHash, string Hash);

public interface IMifStore
{
    Task InitializeAsync(CancellationToken ct);

    /// <summary>Returns false if the event was already handled (by this or an earlier process).</summary>
    Task<bool> TryMarkEventProcessedAsync(string eventId, DateTimeOffset at, CancellationToken ct);

    Task SaveSnapshotAsync(SnapshotRecord snapshot, CancellationToken ct);

    /// <summary>The most recent snapshot of every user, including revoked and expired ones.</summary>
    Task<IReadOnlyList<SnapshotRecord>> GetCurrentSnapshotsAsync(CancellationToken ct);

    Task<SnapshotRecord?> GetSnapshotAsync(string jti, CancellationToken ct);

    /// <summary>Marks every unrevoked snapshot of the user as revoked. Returns how many were affected.</summary>
    Task<int> RevokeUserSnapshotsAsync(string userId, DateTimeOffset at, string reason, CancellationToken ct);

    Task<string?> GetStateAsync(string key, CancellationToken ct);
    Task SetStateAsync(string key, string value, CancellationToken ct);

    Task<AuditRecord?> GetLastAuditAsync(CancellationToken ct);
    Task AppendAuditAsync(AuditRecord record, CancellationToken ct);

    /// <summary>The newest <paramref name="max"/> audit records in ascending order.</summary>
    Task<IReadOnlyList<AuditRecord>> GetAuditAsync(int max, CancellationToken ct);
}
