import Foundation

// SeamsWriter — append-only persister for `seams` rows.
//
// Every anomaly-driven auto-rotation writes exactly one row with the
// signal tag + timestamp + parent secret_name (BR-G-03). The 0034
// trigger enforces append-only at the DB layer; this writer enforces
// it at the call surface by exposing no UPDATE or DELETE method.
//
// Row shape matches 0032_seams.sql one-to-one. Outcome enum maps to
// the CHECK constraint values `rotated|failed|bypassed`.

public actor SeamsWriter {

    public enum Outcome: String, Codable, Sendable, Equatable {
        case rotated
        case failed
        case bypassed
    }

    public struct Row: Codable, Sendable, Equatable {
        public let ts: Date
        public let secretName: String
        public let signal: AnomalySignal
        public let outcome: Outcome
        public let notes: String?

        public init(
            ts: Date,
            secretName: String,
            signal: AnomalySignal,
            outcome: Outcome,
            notes: String?
        ) {
            self.ts = ts
            self.secretName = secretName
            self.signal = signal
            self.outcome = outcome
            self.notes = notes
        }
    }

    /// Review finding U12 — sliding-window cap on the in-memory row
    /// store. Matches `AuditWriter.maxInMemoryRows`. v1.1 DB swap
    /// replaces this with a persistent append-only log.
    public static let maxInMemoryRows: Int = 10_000

    private var rows: [Row] = []

    public init() {}

    /// Append a single seams row. Parameterized over AnomalySignal so that
    /// any of the six signal cases can be serialized into the `signal`
    /// column verbatim.
    ///
    /// Review finding U12 — retires oldest rows once the cap is hit.
    public func append(
        signal: AnomalySignal,
        secret: String,
        outcome: Outcome,
        ts: Date,
        notes: String?
    ) throws {
        rows.append(
            Row(
                ts: ts,
                secretName: secret,
                signal: signal,
                outcome: outcome,
                notes: notes
            )
        )
        if rows.count > Self.maxInMemoryRows {
            rows.removeFirst(rows.count - Self.maxInMemoryRows)
        }
    }

    public func all() -> [Row] {
        rows
    }

    /// Row count (ops-facing).
    public func count() -> Int { rows.count }
}
