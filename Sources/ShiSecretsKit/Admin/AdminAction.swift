import Crypto
import Foundation

// AdminAction — item #9 (BR-F-08 / BR-F-09 / BR-F-10 / BR-F-11).
//
// A human-operator intent envelope, Ed25519-signed by the operator's
// Mac Secure Enclave. Used to gate privileged broker commands
// (currently: revoke-all-bots). The public verification key is the
// SAME pinned key used for MCP manifest verification (Phase 3 Option
// C trust root); the signed `domain` field keeps the two action
// classes separated so a manifest signature cannot be replayed as an
// admin action.
//
// Canonical signing bytes = sorted-keys JSON encoding of the envelope.
// Keeping this stable across implementations is what makes cross-tool
// signing (`shikki-admin-sign`) + broker verification interoperable.

public struct AdminAction: Codable, Sendable, Equatable {

    /// Closed enum of actions the broker accepts. Adding a new action
    /// requires BOTH a code change AND a fresh signing ceremony on the
    /// operator's Mac — new domain = new signed envelope shape.
    public enum ActionKind: String, Codable, Sendable, Equatable {
        case revokeAllBots = "revoke-all-bots"
    }

    /// MUST equal `AdminActionVerifier.expectedDomain`. Domain
    /// separation prevents a manifest-class signature being replayed
    /// as an admin-class signature and vice versa (BR-F-09).
    public let domain: String
    public let action: ActionKind
    /// 22-char base64url, 16 random bytes. The broker rejects a
    /// previously-seen nonce (BR-F-10).
    public let nonce: String
    /// ISO8601; checked ±`AdminActionVerifier.maxSkewSeconds` against
    /// the broker's monotonic clock (BR-F-11).
    public let issuedAt: Date
    /// Audit-only, e.g. "Fr0zenSide@obyw.one". Not a trust input; the
    /// trust root is the pinned pubkey that verifies the signature.
    public let actor: String

    enum CodingKeys: String, CodingKey {
        case domain
        case action
        case nonce
        case issuedAt = "issued_at"
        case actor
    }

    public init(
        domain: String,
        action: ActionKind,
        nonce: String,
        issuedAt: Date,
        actor: String
    ) {
        self.domain = domain
        self.action = action
        self.nonce = nonce
        self.issuedAt = issuedAt
        self.actor = actor
    }

    /// Canonical byte encoding for signing / verifying. Sorted-keys
    /// JSON with ISO8601 dates. Both the signing tool and the
    /// verifier MUST agree on this encoding byte-for-byte or every
    /// signature is a `.badSignature`.
    public func canonicalBytes() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(self)
    }
}

/// Transport wrapper — envelope + detached Ed25519 signature (64
/// bytes raw). The broker's CLI reads this from file or stdin and
/// hands it to `BrokerDaemon.revokeAllBots(signedBy:)`.
public struct SignedAdminAction: Codable, Sendable, Equatable {
    public let envelope: AdminAction
    public let signature: Data

    public init(envelope: AdminAction, signature: Data) {
        self.envelope = envelope
        self.signature = signature
    }
}
