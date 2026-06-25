// SessionStateW65Tests — W6.5
//
// Tests for the W6.5 additions to SessionState (`.lockedBySessionChange`,
// `.needsReauth(reason:)`) and ReauthReason. Verifies Codable round-trip,
// operator-facing string surface, and backward-compat decode of pre-W6.5
// payloads.
//
// Spec UUID: e8c4a921-7d3b-4f5e-9a2c-1d6b8f4e3a91 (W6.5)

import Testing
import Foundation
@testable import ShiSecretsKit

@Suite("SessionState W6.5")
struct SessionStateW65Tests {

    // MARK: - Round-trip

    @Test("T-W6.5-SS-01: .lockedBySessionChange round-trips through Codable")
    func lockedBySessionChange_roundTrips() throws {
        let state = SessionState.lockedBySessionChange
        let data = try JSONEncoder().encode(state)
        let back = try JSONDecoder().decode(SessionState.self, from: data)
        #expect(back == state)
    }

    @Test("T-W6.5-SS-02: .needsReauth(.vaultRevokedKey) round-trips")
    func needsReauthVaultRevoked_roundTrips() throws {
        let state = SessionState.needsReauth(reason: .vaultRevokedKey)
        let data = try JSONEncoder().encode(state)
        let back = try JSONDecoder().decode(SessionState.self, from: data)
        #expect(back == state)
    }

    @Test("T-W6.5-SS-03: every ReauthReason round-trips")
    func allReauthReasons_roundTrip() throws {
        let allReasons: [ReauthReason] = [
            .vaultRevokedKey,
            .upstreamMFAEscalation,
            .clientCredsRotated,
            .sessionFingerprintMismatch,
            .unknown,
        ]
        for reason in allReasons {
            let state = SessionState.needsReauth(reason: reason)
            let data = try JSONEncoder().encode(state)
            let back = try JSONDecoder().decode(SessionState.self, from: data)
            #expect(back == state, "reason=\(reason) did not round-trip cleanly")
        }
    }

    // MARK: - Regression — pre-W6.5 enum cases still encode/decode

    @Test("T-W6.5-SS-04: pre-W6.5 .locked decodes from legacy JSON")
    func legacyLocked_decodes() throws {
        let json = #"{"kind":"locked"}"#
        let data = json.data(using: .utf8)!
        let state = try JSONDecoder().decode(SessionState.self, from: data)
        #expect(state == .locked)
    }

    @Test("T-W6.5-SS-05: pre-W6.5 .unlocked decodes from legacy JSON")
    func legacyUnlocked_decodes() throws {
        let exp = Date(timeIntervalSince1970: 1_780_000_000)
        let formatted = ISO8601DateFormatter().string(from: exp)
        let json = #"{"kind":"unlocked","expiresAt":"\#(formatted)"}"#
        let data = json.data(using: .utf8)!
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let state = try decoder.decode(SessionState.self, from: data)
        if case .unlocked(let decodedExp) = state {
            #expect(Int(decodedExp.timeIntervalSince1970) == Int(exp.timeIntervalSince1970))
        } else {
            try Issue.record("Expected .unlocked, got \(state)")
        }
    }

    // MARK: - Operator-facing strings

    @Test("T-W6.5-SS-06: operatorMessage exists for every W6.5 case + mentions reauth verb")
    func operatorMessages_mentionReauth() throws {
        let locked = SessionState.lockedBySessionChange.operatorMessage
        #expect(locked.lowercased().contains("login --reauth"))

        let revoked = SessionState.needsReauth(reason: .vaultRevokedKey).operatorMessage
        #expect(revoked.lowercased().contains("login --reauth"))
        #expect(revoked.contains(ReauthReason.vaultRevokedKey.rawValue))
    }
}
