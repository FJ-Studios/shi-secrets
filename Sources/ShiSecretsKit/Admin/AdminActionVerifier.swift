import Crypto
import Foundation

// AdminActionVerifier — item #9 (BR-F-08 / BR-F-09 / BR-F-10 / BR-F-11).
//
// Mirrors `ManifestVerifier` in shape: pins an Ed25519 public key at
// provisioning time + verifies incoming envelopes against it. The
// broker NEVER possesses the signing private key — that lives on the
// operator's Mac Secure Enclave and is only used by the external
// `shikki-admin-sign` tool.
//
// Verification flow (fail-fast, in order):
//   1. `envelope.domain` == `expectedDomain` → else `.badDomain`
//   2. `envelope.action` is a known `ActionKind` (handled by Codable
//      decode during transport; the type system enforces this once we
//      hold a `SignedAdminAction` value — case left in the error enum
//      so JSON-RPC decoders at the edge can report it uniformly).
//   3. `|clock() - issuedAt|` ≤ `maxSkewSeconds` → else `.stale`
//   4. `nonce ∉ seenNonces` → else `.replay`
//   5. Ed25519 signature of `envelope.canonicalBytes()` verifies
//      against `pinnedPublicKey` → else `.badSignature`
//   6. Insert nonce into `seenNonces`; return `envelope.action`.
//
// The `seenNonces` set is unbounded today; v1.1 swaps to a persisted
// set or a sliding window keyed on `issuedAt`. See the `v1.1` TODO
// below. This is safe for v1 because the operator signs a handful of
// admin actions per incident — not a spray-source.

public actor AdminActionVerifier {

    public enum VerifyError: Swift.Error, Sendable, Equatable {
        case badSignature
        case badDomain(String)
        case unknownAction(String)
        case stale(issuedAt: Date, now: Date, maxSkewSeconds: Int)
        case replay(nonce: String)
    }

    public static let expectedDomain = "shikki.admin.action.v1"
    /// Tight window — signing on the operator's Mac and submitting
    /// over the Unix socket is a seconds-scale operation. 60s gives
    /// enough slack for NTP skew + ceremony latency without opening a
    /// realistic replay window.
    public static let maxSkewSeconds: Int = 60

    private let pinnedPublicKey: Curve25519.Signing.PublicKey
    private let clock: @Sendable () -> Date
    private var seenNonces: Set<String> = []

    public init(
        pinnedPublicKey: Curve25519.Signing.PublicKey,
        clock: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.pinnedPublicKey = pinnedPublicKey
        self.clock = clock
    }

    /// Verify a `SignedAdminAction`. Throws `VerifyError` on any
    /// refusal; returns the action kind on success + records the
    /// nonce so a second presentation is rejected with `.replay`.
    public func verify(_ signed: SignedAdminAction) throws -> AdminAction.ActionKind {
        let envelope = signed.envelope

        // 1. Domain check — cheap + deterministic; do it first so a
        // manifest-class signature is rejected before we touch the
        // crypto path.
        guard envelope.domain == Self.expectedDomain else {
            throw VerifyError.badDomain(envelope.domain)
        }

        // 2. Freshness window.
        let now = clock()
        let skew = abs(now.timeIntervalSince(envelope.issuedAt))
        if skew > TimeInterval(Self.maxSkewSeconds) {
            throw VerifyError.stale(
                issuedAt: envelope.issuedAt,
                now: now,
                maxSkewSeconds: Self.maxSkewSeconds
            )
        }

        // 3. Replay guard — check BEFORE signature so a replayed
        // previously-valid signature still trips the replay path
        // rather than the (still-valid) signature path.
        if seenNonces.contains(envelope.nonce) {
            throw VerifyError.replay(nonce: envelope.nonce)
        }

        // 4. Signature.
        let bytes: Data
        do {
            bytes = try envelope.canonicalBytes()
        } catch {
            throw VerifyError.badSignature
        }
        guard pinnedPublicKey.isValidSignature(signed.signature, for: bytes) else {
            throw VerifyError.badSignature
        }

        // 5. Commit nonce and return.
        // v1.1 TODO: swap `seenNonces` to a persisted set bounded by
        // `2 * maxSkewSeconds` so process restart + long-running
        // daemons don't grow this unboundedly. For v1 the operator
        // signs O(1) admin actions per incident, so the growth is
        // negligible.
        seenNonces.insert(envelope.nonce)
        return envelope.action
    }
}
