// HankoSigilExchange — W10 (shi-secrets side).
//
// Cross-machine sigil envelope emit + validate. Architectural promise:
// the raw `client_credentials` blob NEVER leaves the originating Keychain.
// The sigil envelope carries ONLY references + proofs:
//
//   { sigil_id, vault_url, token_reference, expires_at,
//     hanko_jwt_proof, machine_id_emitting }
//
// Machine B redeems the sigil_id against the Hanko broker which mints a
// SHORT-LIVED token (≤ 5 min TTL) bound to B's machine_id and returns it.
// `cached_token` is NEVER a member of this envelope by design — both the
// Codable conformance and a regression test enforce this.
//
// W10-T-06 / W10-T-07 baked in as compile-time + runtime guarantees.

import Foundation

// MARK: - SigilEnvelope (strict schema)

public struct SigilEnvelope: Sendable, Codable, Equatable {

    public let sigilID: String           // UUID
    public let vaultURL: String          // https://vw.obyw.one
    public let tokenReference: String    // hanko-broker-issued-jti
    public let expiresAt: Date           // ISO 8601
    public let hankoJWTProof: String     // signed JWT, opaque to shi-secrets
    public let machineIDEmitting: String // UUID of originating machine

    enum CodingKeys: String, CodingKey {
        case sigilID = "sigil_id"
        case vaultURL = "vault_url"
        case tokenReference = "token_reference"
        case expiresAt = "expires_at"
        case hankoJWTProof = "hanko_jwt_proof"
        case machineIDEmitting = "machine_id_emitting"
    }

    public init(
        sigilID: String,
        vaultURL: String,
        tokenReference: String,
        expiresAt: Date,
        hankoJWTProof: String,
        machineIDEmitting: String
    ) {
        self.sigilID = sigilID
        self.vaultURL = vaultURL
        self.tokenReference = tokenReference
        self.expiresAt = expiresAt
        self.hankoJWTProof = hankoJWTProof
        self.machineIDEmitting = machineIDEmitting
    }

    /// Returns true if the envelope is still valid at `now`.
    public func isLive(at now: Date) -> Bool {
        return now < expiresAt
    }
}

// MARK: - HankoBroker abstraction

/// Outbound abstraction for the Hanko broker. Real impl POSTs to the
/// Hanko sigil-redeem endpoint over TLS-pinned HTTPS. Tests inject a
/// fake conforming to this protocol.
public protocol HankoBroker: Sendable {
    /// Asks the broker to mint a short-lived token bound to `machineIDRedeeming`,
    /// against the envelope's `sigil_id`. Returns the minted token + its
    /// expiry (broker-controlled, ≤ 5 min).
    func redeem(envelope: SigilEnvelope, machineIDRedeeming: String) async throws -> HankoMintedToken
}

public struct HankoMintedToken: Sendable, Equatable {
    public let token: String
    public let expiresAt: Date
    public let boundToMachineID: String

    public init(token: String, expiresAt: Date, boundToMachineID: String) {
        self.token = token
        self.expiresAt = expiresAt
        self.boundToMachineID = boundToMachineID
    }
}

// MARK: - HankoSigilExchange

public struct HankoSigilExchange: Sendable {

    private let broker: any HankoBroker
    private let nowProvider: @Sendable () -> Date
    private let uuidProvider: @Sendable () -> String

    public init(
        broker: any HankoBroker,
        nowProvider: @escaping @Sendable () -> Date = { Date() },
        uuidProvider: @escaping @Sendable () -> String = { UUID().uuidString }
    ) {
        self.broker = broker
        self.nowProvider = nowProvider
        self.uuidProvider = uuidProvider
    }

    /// Build an envelope from the originating machine's session. Default TTL
    /// is 1h (configurable per W10-T-03 spec).
    public func emit(
        vaultURL: String,
        tokenReference: String,
        hankoJWTProof: String,
        machineIDEmitting: String,
        ttlSeconds: Int = 3600
    ) -> SigilEnvelope {
        return SigilEnvelope(
            sigilID: uuidProvider(),
            vaultURL: vaultURL,
            tokenReference: tokenReference,
            expiresAt: nowProvider().addingTimeInterval(TimeInterval(ttlSeconds)),
            hankoJWTProof: hankoJWTProof,
            machineIDEmitting: machineIDEmitting
        )
    }

    /// Validate envelope freshness + ask the broker to mint a token bound to
    /// the redeeming machine. Enforces the 5-min ceiling regardless of the
    /// broker's response (lessons-learned regression guard W10-T-07).
    public func redeem(
        envelope: SigilEnvelope,
        machineIDRedeeming: String,
        maxAllowedTokenTTLSeconds: Int = 300
    ) async -> RedeemOutcome {
        let now = nowProvider()
        guard envelope.isLive(at: now) else {
            return .sigilExpired
        }
        guard envelope.machineIDEmitting != machineIDRedeeming else {
            return .sameMachineRefused
        }
        let token: HankoMintedToken
        do {
            token = try await broker.redeem(envelope: envelope, machineIDRedeeming: machineIDRedeeming)
        } catch {
            return .brokerFailed(reason: "\(error)")
        }
        // Enforce TTL ceiling: never accept a broker-issued token that
        // outlives the W10 5-min guarantee, even if the broker returned one.
        let cap = now.addingTimeInterval(TimeInterval(maxAllowedTokenTTLSeconds))
        if token.expiresAt > cap {
            return .brokerTTLViolation(brokerTTL: token.expiresAt, cap: cap)
        }
        guard token.boundToMachineID == machineIDRedeeming else {
            return .machineIDMismatch(expected: machineIDRedeeming, got: token.boundToMachineID)
        }
        return .redeemed(token: token)
    }

    public enum RedeemOutcome: Sendable, Equatable {
        case redeemed(token: HankoMintedToken)
        case sigilExpired
        case sameMachineRefused
        case brokerFailed(reason: String)
        case brokerTTLViolation(brokerTTL: Date, cap: Date)
        case machineIDMismatch(expected: String, got: String)
    }
}
