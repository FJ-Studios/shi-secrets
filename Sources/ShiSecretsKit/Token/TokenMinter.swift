import Crypto
import Foundation

// TokenMinter — signs ShikkiSBT envelopes under the broker's active
// Ed25519 signing key and inserts the resulting row into TokenRegistry.
//
// Wave 2 scope:
//   - BR-A-01   Ed25519 COSE_Sign1 scheme (exposed via SignatureScheme)
//   - BR-A-13   llm_touched set server-side from transport metadata only
//   - BR-D-04   MCP transport → llm_touched=TRUE
//   - BR-D-05   Unix transport → llm_touched=FALSE (default)
//   - BR-E-01   llm_touched TTL ≤ 3600 (ShikkiSBT.Claims.validate enforces)
//   - BR-H-03   Request type has no `llmTouched` field — caller can't smuggle
//   - BR-H-05   Op mismatch vs signed manifest schema → opMismatch error
//   - BR-A-05   inserts row into TokenRegistry (dup jti rejected there)
//
// The envelope produced here is a detached Ed25519 signature over the
// canonicalized Claims JSON (sorted keys, ISO-8601 dates). Full
// COSE_Sign1 header wrapping can be added once the on-the-wire format is
// locked with the MCP transport; the canonical-JSON subset suffices for
// the verification path in Wave 2.

public actor TokenMinter {

    public enum SignatureScheme: String, Sendable, Equatable {
        case ed25519COSESign1
    }

    public enum MintError: Swift.Error, Sendable, Equatable {
        case opMismatch
        case toolNotInManifest(toolName: String)
        /// Review finding U15 — MCP transport MUST always include a
        /// `toolName`. The bridge cannot issue a request without an
        /// invoking tool; a nil toolName on MCP signals a protocol bug
        /// upstream and we refuse at the mint boundary.
        case toolNameRequiredForMCP
    }

    public struct Request: Sendable, Equatable {
        public let sub: String
        public let scope: String
        public let op: ShikkiSBT.Op
        public let ttl: Int
        public let toolName: String?      // MCP-invoked tool (for op-gate)

        public init(sub: String, scope: String, op: ShikkiSBT.Op, ttl: Int, toolName: String?) {
            self.sub = sub
            self.scope = scope
            self.op = op
            self.ttl = ttl
            self.toolName = toolName
        }
    }

    public struct Token: Sendable, Equatable {
        public let claims: ShikkiSBT.Claims
        public let envelope: Data
    }

    public nonisolated let signatureScheme: SignatureScheme = .ed25519COSESign1

    private let registry: TokenRegistry
    private let signingKey: Curve25519.Signing.PrivateKey
    private let toolManifest: [ManifestVerifier.ToolEntry]

    public init(
        registry: TokenRegistry,
        signingKey: Curve25519.Signing.PrivateKey,
        toolManifest: [ManifestVerifier.ToolEntry]
    ) {
        self.registry = registry
        self.signingKey = signingKey
        self.toolManifest = toolManifest
    }

    /// Mints a new token. Caller supplies the request; transport metadata
    /// (MCP vs Unix) drives the `llm_touched` flag per BR-A-13 / BR-D-04
    /// / BR-D-05. Throws on op-mismatch, TTL-ceiling breach, or duplicate
    /// jti.
    ///
    /// Review finding U2 — signing runs BEFORE the registry insert. If
    /// signing / validation throws, the registry is never touched and no
    /// phantom row exists. If the insert fails (e.g. duplicate jti race
    /// in v1.1 DB swap), the signed envelope is discarded by the caller.
    public func mint(
        request: Request,
        transport: AuditRow.Transport,
        peerUid: Int32?,
        now: Date = Date()
    ) async throws -> Token {
        let prepared = try prepare(request: request, transport: transport, now: now)
        try await persist(prepared: prepared)
        _ = peerUid   // currently used only for auditing hook in Wave 4
        return prepared.token
    }

    /// A token whose claims are signed but not yet persisted into the
    /// registry. Review finding U1 — `BrokerDaemon.handleRequest` audits
    /// the allow row BEFORE calling `persist`; if audit fails the row is
    /// never inserted and no phantom token exists. BR-A-05 still holds —
    /// every successfully-returned token has a registry row.
    public struct Prepared: Sendable {
        public let token: Token
        public let row: TokenRegistry.Row
    }

    /// Build + sign claims without persisting. Review finding U2 — signing
    /// is the irreversible-on-failure step; if it throws, no registry row
    /// was ever created.
    public func prepare(
        request: Request,
        transport: AuditRow.Transport,
        now: Date = Date()
    ) throws -> Prepared {
        // BR-H-05 — op-gate against the signed manifest.
        // Review finding U15 — MCP transport MUST include a toolName.
        if transport == .mcp && request.toolName == nil {
            throw MintError.toolNameRequiredForMCP
        }
        if let toolName = request.toolName {
            guard let tool = toolManifest.first(where: { $0.toolName == toolName }) else {
                throw MintError.toolNotInManifest(toolName: toolName)
            }
            if tool.op != request.op {
                throw MintError.opMismatch
            }
        }

        // BR-D-04/05 — transport-driven llm_touched (never from caller).
        let llmTouched: Bool = (transport == .mcp)

        let jti = nextJti(at: now)
        let nbf = now
        let diesAt = nbf.addingTimeInterval(TimeInterval(request.ttl))
        let claims = ShikkiSBT.Claims(
            sub: request.sub,
            scope: request.scope,
            op: request.op,
            ttl: request.ttl,
            jti: jti,
            nbf: nbf,
            diesAt: diesAt,
            llmTouched: llmTouched
        )
        // BR-A-02, BR-A-03, BR-A-06 — claim validation.
        try claims.validate()

        // Detached Ed25519 signature over canonicalized JSON.
        let canonical = try Self.canonicalize(claims)
        let signature = try signingKey.signature(for: canonical)
        let envelope = Data(signature)

        let row = TokenRegistry.Row(
            jti: jti,
            sub: request.sub,
            scope: request.scope,
            op: request.op,
            nbf: nbf,
            diesAt: diesAt,
            llmTouched: llmTouched,
            passkeyPath: false
        )
        return Prepared(token: Token(claims: claims, envelope: envelope), row: row)
    }

    /// Inserts the prepared row into the registry. Call AFTER the audit
    /// allow row has been committed (review finding U1). BR-A-05 dup-jti
    /// still rejects at the registry boundary.
    public func persist(prepared: Prepared) async throws {
        try await registry.insert(prepared.row)
    }

    /// Compensating action — revokes a jti the daemon inserted but whose
    /// audit row then failed. Review finding U2 — documented but the
    /// preferred path is to audit BEFORE persist so this helper is rarely
    /// needed; it exists so ops tooling can keep the two writers aligned.
    public func compensateRevoke(jti: String, at ts: Date = Date()) async {
        try? await registry.revoke(jti: jti, at: ts)
    }

    /// Canonical JSON form of the claims, used as the Ed25519 signing
    /// input + verifier input.
    public static func canonicalize(_ claims: ShikkiSBT.Claims) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(claims)
    }

    /// Generates a proper ULID: 48-bit millisecond timestamp + 80-bit
    /// random, Crockford base32-encoded, 26 chars. Review finding U9 —
    /// uses `SystemRandomNumberGenerator` for the entropy half so two
    /// broker processes starting in the same millisecond cannot collide
    /// (the random half gives ~1.2e24 combinations per ms).
    ///
    /// 3rd-pass validator I3 — the timestamp half is now sourced from
    /// the caller's `at:` parameter (defaults to `Date()`), so tests can
    /// drive the full 128-bit uniqueness surface (timestamp ms advances
    /// + random half differs). The previous version hard-coded
    /// `Date()` inside nextJti, so `ConcurrentMint` tests only
    /// exercised the 80-bit random half.
    ///
    /// Layout:
    ///   bits 127..80 = 48-bit unsigned ms since epoch (big-endian)
    ///   bits  79..0  = 80-bit random
    /// Encoded as 10 Crockford chars of timestamp + 16 chars of random,
    /// matching the ULID spec.
    private func nextJti(at: Date = Date()) -> String {
        let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
        let tsMillis = UInt64(at.timeIntervalSince1970 * 1000) & 0x0000_FFFF_FFFF_FFFF
        var rng = SystemRandomNumberGenerator()
        // Split the 80-bit random into two 64-bit draws; only the low
        // 80 bits across both are consumed.
        let randHi: UInt64 = rng.next() & 0xFFFF          // top 16 bits of the 80-bit half
        let randLo: UInt64 = rng.next()                   // bottom 64 bits

        // Encode timestamp (10 chars).
        var tsChars: [Character] = []
        var tsVal = tsMillis
        for _ in 0 ..< 10 {
            tsChars.append(alphabet[Int(tsVal & 0x1F)])
            tsVal >>= 5
        }
        let tsStr = String(tsChars.reversed())

        // Encode random half (16 chars). Pack the 80 bits back into a
        // 128-bit-ish sequence, 5 bits at a time.
        var randChars: [Character] = []
        var loVal = randLo
        for _ in 0 ..< 12 {
            randChars.append(alphabet[Int(loVal & 0x1F)])
            loVal >>= 5
        }
        // The 12th shift consumed bits 55..59; bits 60..63 remain in the
        // low-16-bit hi-half. Carry 4 bits from loVal into hi for the
        // last 4 chars. Simpler: compose as a 16-bit hi + remaining 4 bits.
        // Concat: [randHi (16 bits)] << 4 | (loVal & 0xF) spread.
        let combinedHi: UInt64 = (randHi << 4) | (loVal & 0xF)
        var hi = combinedHi
        for _ in 0 ..< 4 {
            randChars.append(alphabet[Int(hi & 0x1F)])
            hi >>= 5
        }
        let randStr = String(randChars.reversed())
        return tsStr + randStr
    }
}
