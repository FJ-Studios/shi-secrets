import Foundation

// TokenRegistry — append-only registry of every ShikkiSBT issued by the
// broker. Persists ONLY jti + claim metadata (BR-A-07 — no token bytes
// ever reach storage).
//
// Wave 2 note: this actor currently stores rows in an in-memory
// Dictionary protected by actor isolation. The row shape matches the
// 0033_token_registry.sql schema column-for-column so the Wave 4 swap
// to a real ShikkiDB driver is a persistence-adapter change, not a
// domain-model change. Documented deviation — see
// `features/shikki-secrets-broker.md` Implementation Log.
//
// BR coverage:
//   BR-A-05  duplicate jti rejected + ULID validation
//   BR-A-07  no token bytes persisted (Row has no `bytes` column)
//   BR-A-10  isRevoked + revoked rejected regardless of diesAt
//   BR-A-11  markRotateUsed — replay detection (op=rotate single-use)
//   BR-F-01  revokeAllBots — atomic TX over non-passkey rows
//   BR-F-02  revokeAllBots — passkey_path=TRUE rows untouched
//   BR-F-06  revoke(jti:) — no cascade to other tokens sharing sub
//   BR-J-06  revoked rows retained indefinitely (never hard-deleted)

public actor TokenRegistry {

    public struct Row: Sendable, Codable, Equatable {
        public let jti: String
        public let sub: String
        public let scope: String
        public let op: ShikkiSBT.Op
        public let nbf: Date
        public let diesAt: Date
        public let llmTouched: Bool
        public let passkeyPath: Bool
        public var revoked: Bool
        public var revokedAt: Date?

        enum CodingKeys: String, CodingKey {
            case jti
            case sub
            case scope
            case op
            case nbf
            case diesAt      = "dies_at"
            case llmTouched  = "llm_touched"
            case passkeyPath = "passkey_path"
            case revoked
            case revokedAt   = "revoked_at"
        }

        public init(
            jti: String,
            sub: String,
            scope: String,
            op: ShikkiSBT.Op,
            nbf: Date,
            diesAt: Date,
            llmTouched: Bool,
            passkeyPath: Bool,
            revoked: Bool = false,
            revokedAt: Date? = nil
        ) {
            self.jti = jti
            self.sub = sub
            self.scope = scope
            self.op = op
            self.nbf = nbf
            self.diesAt = diesAt
            self.llmTouched = llmTouched
            self.passkeyPath = passkeyPath
            self.revoked = revoked
            self.revokedAt = revokedAt
        }
    }

    public enum TransactionError: Swift.Error, Sendable, Equatable {
        case rolledBack(reason: String)
    }

    // Storage: jti → Row. Dictionary for O(1) duplicate detection.
    private var rows: [String: Row] = [:]
    // Per-jti flag capturing whether `op=rotate` has been presented once.
    private var rotateUsed: Set<String> = []

    /// 3rd-pass validator T1 — test-only fault injection.
    /// Production callers leave this nil. Tests set it to a closure
    /// returning a thrown error to exercise the persist-failure /
    /// compensateRevoke path in BrokerDaemon.
    ///
    /// The seam is strictly additive: `insert` consults the closure
    /// BEFORE touching `rows`. If the closure returns a non-nil error
    /// the row is never inserted, matching a v1.1 DB-layer failure
    /// (disk full, connection drop, etc.).
    private var _testInsertFaultInjector: (@Sendable (Row) -> Swift.Error?)?

    /// Review finding U4 — monotonic counter bumped on every
    /// `revokeAllBots`. TokenVerifier captures the epoch at entry and
    /// re-checks at exit; if the epoch changed AND the verified jti is
    /// now revoked, the verifier returns `.tokenRevoked` instead of a
    /// stale allow. Closes the revoke-vs-verify race.
    private var _revokeEpoch: UInt64 = 0

    public init() {}

    // MARK: - Insert (T13)

    /// BR-A-05 + BR-A-07 — inserts a new row, rejecting duplicate jti or
    /// malformed (non-ULID) jti. Stores metadata only.
    ///
    /// 3rd-pass validator T1 — consults the optional
    /// `_testInsertFaultInjector` FIRST so tests can exercise the
    /// persist-failure path in BrokerDaemon without a v1.1 DB swap.
    /// Production callers never set the injector; the branch is dead
    /// code at runtime.
    public func insert(_ row: Row) throws {
        if let injector = _testInsertFaultInjector, let error = injector(row) {
            throw error
        }
        try Self.validateULID(row.jti)
        if rows[row.jti] != nil {
            throw ShikkiSBT.Error.duplicateJti(jti: row.jti)
        }
        rows[row.jti] = row
    }

    /// 3rd-pass validator T1 — test-only setter for the insert fault
    /// injector. `internal` so only `@testable import` call sites reach
    /// it; the public API surface is unchanged.
    func setTestInsertFaultInjector(_ injector: (@Sendable (Row) -> Swift.Error?)?) {
        _testInsertFaultInjector = injector
    }

    /// Test + audit-reader accessor for a persisted row. Review finding
    /// U18 — demoted to `internal` so snapshot tests use `@testable
    /// import ShiSecretsKit` rather than leaving the accessor on the
    /// public API surface.
    func row(jti: String) -> Row? {
        rows[jti]
    }

    /// Test + audit-reader snapshot. Review finding U18 — demoted to
    /// `internal`; call sites `@testable import` the module.
    func all() -> [Row] {
        Array(rows.values)
    }

    /// Review finding U4 — current revoke epoch. TokenVerifier uses this
    /// to detect whether a concurrent `revokeAllBots` ran while a
    /// verification was in-flight.
    public var revokeEpoch: UInt64 { _revokeEpoch }

    // MARK: - Revocation (T14)

    /// BR-A-10 + BR-F-06 — marks a single jti revoked. No cascade to
    /// other tokens sharing the same `sub`. The row is retained for
    /// audit (BR-J-06: never hard-deleted).
    public func revoke(jti: String, at ts: Date = Date()) throws {
        guard var row = rows[jti] else {
            // Review finding U19 — dedicated case disambiguates
            // "no such jti" from "jti was missing in the claim set".
            throw ShikkiSBT.Error.invalidJti(reason: "jti not registered")
        }
        row.revoked = true
        row.revokedAt = ts
        rows[jti] = row
    }

    public func isRevoked(jti: String) -> Bool {
        rows[jti]?.revoked ?? false
    }

    // MARK: - revokeAllBots (T15)

    /// BR-F-01 + BR-F-02 — atomically revokes every non-passkey_path row
    /// that is not already revoked. On any failure, the whole transaction
    /// rolls back (no partial state). Passkey-path rows are never touched.
    ///
    /// The optional `shouldFail` closure lets tests inject a failure to
    /// exercise the rollback path; production callers pass `nil`.
    @discardableResult
    public func revokeAllBots(
        at ts: Date = Date(),
        shouldFail: ((Row) -> Bool)? = nil
    ) throws -> Int {
        // Snapshot for rollback.
        let snapshot = rows
        var count = 0
        do {
            for (jti, row) in rows {
                if row.passkeyPath || row.revoked {
                    continue
                }
                if let shouldFail, shouldFail(row) {
                    throw TransactionError.rolledBack(reason: "injected failure on \(jti)")
                }
                var updated = row
                updated.revoked = true
                updated.revokedAt = ts
                rows[jti] = updated
                count += 1
            }
            // Review finding U4 — bump the revoke epoch AFTER the TX
            // commits so TokenVerifier can detect a window-overlap.
            _revokeEpoch &+= 1
            return count
        } catch {
            rows = snapshot
            throw error
        }
    }

    // MARK: - markRotateUsed (T16)

    /// BR-A-11 — first presentation of `op=rotate` for a jti is accepted.
    /// Second presentation throws `replay(jti:)` and is never recorded as
    /// used again.
    public func markRotateUsed(jti: String) throws {
        if rotateUsed.contains(jti) {
            throw ShikkiSBT.Error.replay(jti: jti)
        }
        rotateUsed.insert(jti)
    }

    public func isReplay(jti: String) -> Bool {
        rotateUsed.contains(jti)
    }

    // MARK: - ULID validation

    /// Crockford base32 alphabet used by `validateULID`. Review finding
    /// #15 — hoisted to a `static let` so the Set is not rebuilt on every
    /// `mint` call (hot path).
    private static let crockfordAlphabet: Set<Character> = Set("0123456789ABCDEFGHJKMNPQRSTVWXYZ")

    /// A permissive ULID shape check: 26 chars, Crockford base32 alphabet.
    /// Collision probability at 128 bits is negligible; format correctness
    /// is enough to satisfy BR-A-05 at the registry boundary.
    ///
    /// Review finding U19 — ULID shape failures surface as
    /// `invalidJti(reason:)` rather than the catch-all
    /// `missingClaim(name: "jti")` so audit logs are diagnostic.
    public static func validateULID(_ candidate: String) throws {
        guard candidate.count == 26 else {
            throw ShikkiSBT.Error.invalidJti(reason: "expected 26 chars, got \(candidate.count)")
        }
        for ch in candidate {
            if !Self.crockfordAlphabet.contains(ch) {
                throw ShikkiSBT.Error.invalidJti(reason: "non-Crockford character: \(ch)")
            }
        }
    }
}
