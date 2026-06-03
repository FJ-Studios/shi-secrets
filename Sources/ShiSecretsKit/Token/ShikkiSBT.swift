import Foundation

// ShikkiSBT — the broker's short-lived signed bearer token envelope.
//
// Wave 1 delivers the claims shape, the Op enum, and the Error enum. The
// Ed25519 / COSE_Sign1 verify() method and on-the-wire envelope bytes land
// in Wave 2 alongside the TokenMinter / TokenVerifier actors.
//
// BR-A-02 requires eight claims; BR-A-04 limits `op` to read/rotate; BR-A-06
// reserves `dies_at` as the only expiry surface (no "expires_at" anywhere).
// The full list of rejection reasons is surfaced through `ShikkiSBT.Error`
// so the broker can feed a machine-readable `DenyReason` into `secret_audit`.

public struct ShikkiSBT: Sendable, Equatable {

    /// The eight claims that MUST appear on every issued token (BR-A-02).
    public struct Claims: Codable, Sendable, Equatable {
        public let sub: String
        public let scope: String
        public let op: Op
        public let ttl: Int
        public let jti: String
        public let nbf: Date
        public let diesAt: Date
        public let llmTouched: Bool

        enum CodingKeys: String, CodingKey {
            case sub
            case scope
            case op
            case ttl
            case jti
            case nbf
            case diesAt = "dies_at"
            case llmTouched = "llm_touched"
        }

        public init(
            sub: String,
            scope: String,
            op: Op,
            ttl: Int,
            jti: String,
            nbf: Date,
            diesAt: Date,
            llmTouched: Bool
        ) {
            self.sub = sub
            self.scope = scope
            self.op = op
            self.ttl = ttl
            self.jti = jti
            self.nbf = nbf
            self.diesAt = diesAt
            self.llmTouched = llmTouched
        }
    }

    public enum Op: String, Codable, Sendable, Equatable {
        case read
        case rotate
    }

    public enum Error: Swift.Error, Sendable, Equatable {
        case tokenExpired
        case tokenNotYetValid
        case tokenRevoked
        case badSignature
        case replay(jti: String)
        case missingClaim(name: String)
        case ttlAbove3600
        case invalidOp(raw: String)
        case duplicateJti(jti: String)
        case serializationLeakedExpiresAt
        /// Review finding U19 — dedicated cases for jti / dies_at /
        /// claim-format failures. `missingClaim` was overloaded as a
        /// catch-all; these variants make audit rows + logs
        /// human-readable.
        case invalidJti(reason: String)
        case badDiesAt
        case claimFormatInvalid(name: String, reason: String)
    }

    public let claims: Claims

    public init(claims: Claims) {
        self.claims = claims
    }
}

// MARK: - Validation

extension ShikkiSBT.Claims {

    /// Tolerance (seconds) for the `dies_at == nbf + ttl` equality check.
    /// Floating-point clock math can introduce sub-microsecond skew; 1 second
    /// is safely below the 3600-second TTL ceiling while catching operational
    /// bugs that shift dies_at by whole seconds.
    public static let diesAtTolerance: TimeInterval = 1.0

    /// Validates a freshly-constructed claim set against BR-A-02 / BR-A-03 /
    /// BR-A-06 before the broker signs it. Throws the first violation.
    ///
    /// - `sub`, `scope`, `jti` MUST be non-empty strings (BR-A-02).
    /// - `ttl` MUST be in the range (0, 3600] (BR-A-03).
    /// - `dies_at` MUST equal `nbf + ttl` within `diesAtTolerance` (BR-A-06).
    /// - The JSON-serialized form MUST NOT contain the substring
    ///   "expires_at" (BR-A-06 hygiene — enforced so a future mistaken
    ///   CodingKey addition cannot ship a second expiry surface).
    public func validate() throws {
        if sub.isEmpty {
            throw ShikkiSBT.Error.missingClaim(name: "sub")
        }
        if scope.isEmpty {
            throw ShikkiSBT.Error.missingClaim(name: "scope")
        }
        if jti.isEmpty {
            throw ShikkiSBT.Error.missingClaim(name: "jti")
        }
        if ttl <= 0 {
            throw ShikkiSBT.Error.claimFormatInvalid(name: "ttl", reason: "must be > 0")
        }
        if ttl > 3600 {
            throw ShikkiSBT.Error.ttlAbove3600
        }
        let expectedDiesAt = nbf.addingTimeInterval(TimeInterval(ttl))
        if abs(diesAt.timeIntervalSince(expectedDiesAt)) > ShikkiSBT.Claims.diesAtTolerance {
            // Review finding U19 — dedicated case disambiguates from
            // "missing claim". The audit trail / logs now carry
            // `badDiesAt` instead of `missingClaim(name: "dies_at")`.
            throw ShikkiSBT.Error.badDiesAt
        }
        // BR-A-06 hygiene scan — guards against a future CodingKeys change
        // accidentally reintroducing "expires_at" into the serialized output.
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(self),
              let json = String(data: data, encoding: .utf8) else {
            // If we cannot serialize the claims, defer to the caller's own
            // Codable error handling — the validator only asserts content.
            return
        }
        if json.contains("expires_at") {
            throw ShikkiSBT.Error.serializationLeakedExpiresAt
        }
    }
}
