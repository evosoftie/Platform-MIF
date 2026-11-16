using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Mif.Node.Storage;

namespace Mif.Node.Audit;

/// <summary>
/// Append-only, hash-chained record of every continuity decision. Each record commits to the one
/// before it, so editing or deleting history is detectable by <see cref="VerifyChain"/>.
/// </summary>
public sealed class AuditLog(IMifStore store, TimeProvider time, ILogger<AuditLog> log)
{
    public const string Genesis = "genesis";

    private readonly SemaphoreSlim _gate = new(1, 1);
    private string? _lastHash;

    public async Task WriteAsync(string type, string? subject, object data, CancellationToken ct)
    {
        var json = JsonSerializer.Serialize(data);
        // Millisecond precision so the stored value hashes the same after a round trip through the database.
        var at = DateTimeOffset.FromUnixTimeMilliseconds(time.GetUtcNow().ToUnixTimeMilliseconds());

        await _gate.WaitAsync(ct);
        try
        {
            _lastHash ??= (await store.GetLastAuditAsync(ct))?.Hash ?? Genesis;
            var hash = ComputeHash(_lastHash, at, type, subject, json);
            await store.AppendAuditAsync(new AuditRecord(0, at, type, subject, json, _lastHash, hash), ct);
            _lastHash = hash;
        }
        finally
        {
            _gate.Release();
        }

        log.LogInformation("audit {Type} subject={Subject} {Data}", type, subject, json);
    }

    public static string ComputeHash(string prevHash, DateTimeOffset at, string type, string? subject, string data) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(
            string.Join('\n', prevHash, at.ToUnixTimeMilliseconds(), type, subject ?? "", data))));

    /// <summary>Checks that every record hashes correctly and links to its predecessor within the given window.</summary>
    public static bool VerifyChain(IReadOnlyList<AuditRecord> records)
    {
        for (var i = 0; i < records.Count; i++)
        {
            var r = records[i];
            if (r.Hash != ComputeHash(r.PrevHash, r.At, r.Type, r.Subject, r.Data)) return false;
            if (i > 0 && r.PrevHash != records[i - 1].Hash) return false;
        }
        return true;
    }
}
