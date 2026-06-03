import Foundation

// AuditWriter — append-only persister for `secret_audit` rows.
//
// BR-G-01 requires exactly one row per token-validated fetch before
// plaintext is returned to the caller; BR-G-02 / BR-J-05 forbid any
// plaintext, ciphertext, or token bytes in persisted rows. The 0034
// trigger guards the DB-level append-only invariant; this writer adds
// a body-scanner that rejects oversized `secret_name` payloads before
// the INSERT ever reaches SQLite.
//
// Wave 2 stores rows in an in-memory array protected by actor isolation.
// Wave 4 swaps the backend for the real ShikkiDB driver without changing
// the call surface — the row shape already matches migration 0031.

public actor AuditWriter {

    public enum AppendError: Swift.Error, Sendable, Equatable {
        /// secret_name exceeded 64 characters — likely a payload smuggle
        /// (BR-J-05 — column is a reference name only).
        case secretNameTooLong(length: Int)
        /// A deny row was presented without a machine-readable reason
        /// (BR-G-04 — every deny row MUST carry a DenyReason).
        case denyRowMissingReason
    }

    /// Hard cap for `secret_audit.secret_name` (reference names only; no
    /// payload ever flows through this column per BR-J-05).
    public static let maxSecretNameLength = 64

    /// Review finding U12 — sliding-window cap on the in-memory row
    /// store. A retry-stuck vendor loop can spam rows indefinitely; once
    /// we exceed this count the oldest rows rotate out. v1.1 DB swap
    /// replaces this with a persistent append-only log; until then the
    /// cap keeps memory bounded. Ops-visible via `count()`.
    public static let maxInMemoryRows: Int = 10_000

    private var rows: [AuditRow] = []

    public init() {}

    /// Appends a single audit row. Rejects oversized secret_name (payload
    /// smuggle guard) and deny rows without a reason. No UPDATE / DELETE
    /// surface is exposed — BR-G-05 is enforced by omission.
    ///
    /// Review finding U12 — if the cap is reached, the oldest row is
    /// dropped to keep memory bounded. The behavior is the Wave 2 / 4
    /// in-memory compromise; v1.1's DB-backed writer retains every row.
    public func append(_ row: AuditRow) throws {
        if row.secretName.count > Self.maxSecretNameLength {
            throw AppendError.secretNameTooLong(length: row.secretName.count)
        }
        if row.allow == .deny && row.reason == nil {
            throw AppendError.denyRowMissingReason
        }
        rows.append(row)
        if rows.count > Self.maxInMemoryRows {
            rows.removeFirst(rows.count - Self.maxInMemoryRows)
        }
    }

    /// Test + audit-reader accessor. Returns a snapshot of currently-
    /// persisted rows in insertion order.
    public func all() -> [AuditRow] {
        rows
    }

    /// Count of persisted rows (used by writer-level invariants).
    public func count() -> Int {
        rows.count
    }
}
