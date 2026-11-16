namespace Mif.Node.Storage;

/// <summary>Volatile store for development and tests. Use Postgres for anything that must survive a restart.</summary>
public sealed class InMemoryMifStore : IMifStore
{
    private readonly Lock _gate = new();
    private readonly HashSet<string> _events = [];
    private readonly Dictionary<string, SnapshotRecord> _snapshots = [];
    private readonly Dictionary<string, string> _state = [];
    private readonly List<AuditRecord> _audit = [];

    public Task InitializeAsync(CancellationToken ct) => Task.CompletedTask;

    public Task<bool> TryMarkEventProcessedAsync(string eventId, DateTimeOffset at, CancellationToken ct)
    {
        lock (_gate) return Task.FromResult(_events.Add(eventId));
    }

    public Task SaveSnapshotAsync(SnapshotRecord snapshot, CancellationToken ct)
    {
        lock (_gate) _snapshots[snapshot.Jti] = snapshot;
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<SnapshotRecord>> GetCurrentSnapshotsAsync(CancellationToken ct)
    {
        lock (_gate)
        {
            IReadOnlyList<SnapshotRecord> current = [.. _snapshots.Values
                .GroupBy(s => s.UserId)
                .Select(g => g.OrderByDescending(s => s.VerifiedAt).First())];
            return Task.FromResult(current);
        }
    }

    public Task<SnapshotRecord?> GetSnapshotAsync(string jti, CancellationToken ct)
    {
        lock (_gate) return Task.FromResult(_snapshots.GetValueOrDefault(jti));
    }

    public Task<int> RevokeUserSnapshotsAsync(string userId, DateTimeOffset at, string reason, CancellationToken ct)
    {
        lock (_gate)
        {
            var targets = _snapshots.Values.Where(s => s.UserId == userId && s.RevokedAt is null).ToList();
            foreach (var s in targets) _snapshots[s.Jti] = s with { RevokedAt = at, RevokedReason = reason };
            return Task.FromResult(targets.Count);
        }
    }

    public Task<string?> GetStateAsync(string key, CancellationToken ct)
    {
        lock (_gate) return Task.FromResult(_state.GetValueOrDefault(key));
    }

    public Task SetStateAsync(string key, string value, CancellationToken ct)
    {
        lock (_gate) _state[key] = value;
        return Task.CompletedTask;
    }

    public Task<AuditRecord?> GetLastAuditAsync(CancellationToken ct)
    {
        lock (_gate) return Task.FromResult(_audit.LastOrDefault());
    }

    public Task AppendAuditAsync(AuditRecord record, CancellationToken ct)
    {
        lock (_gate) _audit.Add(record with { Seq = _audit.Count + 1 });
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<AuditRecord>> GetAuditAsync(int max, CancellationToken ct)
    {
        lock (_gate)
        {
            IReadOnlyList<AuditRecord> page = [.. _audit.TakeLast(max)];
            return Task.FromResult(page);
        }
    }

    /// <summary>Test hook: overwrite a stored audit record, as an attacker with database access could.</summary>
    public void TamperWithAudit(int index, Func<AuditRecord, AuditRecord> change)
    {
        lock (_gate) _audit[index] = change(_audit[index]);
    }
}
