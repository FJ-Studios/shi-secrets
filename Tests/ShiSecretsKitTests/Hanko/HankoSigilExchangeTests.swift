// HankoSigilExchangeTests — W10 (shi-secrets side).
//
// Test ID mapping:
//   T-W10-01 → emit_creates_envelope_with_required_fields_only
//   T-W10-03 → ttl_default_1h_configurable_via_param
//   T-W10-06 (REGRESSION) → envelope_does_not_contain_cached_token
//   T-W10-07 (REGRESSION) → broker_TTL_violation_capped_at_5min
//   redeem: happy + sigilExpired + sameMachineRefused + machineIDMismatch

import Foundation
import Testing
@testable import ShiSecretsKit

actor FakeHankoBroker: HankoBroker {
    private let token: HankoMintedToken?
    private let error: Error?
    init(token: HankoMintedToken? = nil, error: Error? = nil) {
        self.token = token; self.error = error
    }
    func redeem(envelope: SigilEnvelope, machineIDRedeeming: String) async throws -> HankoMintedToken {
        if let e = error { throw e }
        return token!
    }
}

struct FakeBrokerError: Error {}

// MARK: - emit (T-W10-01, T-W10-03)

@Suite("W10 SigilEnvelope.emit — schema strictness (T-W10-01, T-W10-03, T-W10-06)")
struct SigilEmitTests {

    @Test("emit produces envelope with all required fields + no extras")
    func emitProducesEnvelope() {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let exchange = HankoSigilExchange(
            broker: FakeHankoBroker(token: HankoMintedToken(token: "x", expiresAt: now, boundToMachineID: "B")),
            nowProvider: { now },
            uuidProvider: { "00000000-0000-0000-0000-000000000001" }
        )
        let env = exchange.emit(
            vaultURL: "https://vw.obyw.one",
            tokenReference: "jti-123",
            hankoJWTProof: "signed.jwt.proof",
            machineIDEmitting: "A"
        )
        #expect(env.sigilID == "00000000-0000-0000-0000-000000000001")
        #expect(env.vaultURL == "https://vw.obyw.one")
        #expect(env.tokenReference == "jti-123")
        #expect(env.hankoJWTProof == "signed.jwt.proof")
        #expect(env.machineIDEmitting == "A")
        // CRIT-3 fix: default TTL is now 300s (was 3600s).
        #expect(env.expiresAt == now.addingTimeInterval(300))
    }

    @Test("default TTL is 300s; custom ttl below cap honored (T-W10-03)")
    func customTTLBelowCap() {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let exchange = HankoSigilExchange(
            broker: FakeHankoBroker(token: HankoMintedToken(token: "x", expiresAt: now, boundToMachineID: "B")),
            nowProvider: { now }
        )
        let env = exchange.emit(
            vaultURL: "https://x",
            tokenReference: "r",
            hankoJWTProof: "p",
            machineIDEmitting: "A",
            ttlSeconds: 120
        )
        #expect(env.expiresAt == now.addingTimeInterval(120))
    }

    @Test("CRIT-3: TTL above envelopeMaxTTLSeconds is capped at 300s")
    func ttlCapEnforced() {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let exchange = HankoSigilExchange(
            broker: FakeHankoBroker(token: HankoMintedToken(token: "x", expiresAt: now, boundToMachineID: "B")),
            nowProvider: { now }
        )
        let env = exchange.emit(
            vaultURL: "https://x",
            tokenReference: "r",
            hankoJWTProof: "p",
            machineIDEmitting: "A",
            ttlSeconds: 3600     // requested 1h, must be capped at 300s
        )
        #expect(env.expiresAt == now.addingTimeInterval(300))
    }

    @Test("envelope encoded as JSON has NO cached_token field (T-W10-06 regression)")
    func noCachedToken() throws {
        let env = SigilEnvelope(
            sigilID: "uid",
            vaultURL: "https://x",
            tokenReference: "r",
            expiresAt: Date(timeIntervalSince1970: 1_700_000_000),
            hankoJWTProof: "p",
            machineIDEmitting: "A"
        )
        let enc = JSONEncoder()
        let data = try enc.encode(env)
        let raw = String(data: data, encoding: .utf8) ?? ""
        #expect(!raw.lowercased().contains("cached_token"))
        #expect(!raw.lowercased().contains("client_secret"))
        #expect(!raw.lowercased().contains("client_id"))
        // All canonical keys present.
        for key in ["sigil_id", "vault_url", "token_reference", "expires_at", "hanko_jwt_proof", "machine_id_emitting"] {
            #expect(raw.contains(key))
        }
    }
}

// MARK: - redeem (T-W10-07 + outcomes)

@Suite("W10 HankoSigilExchange.redeem — outcomes")
struct SigilRedeemTests {

    static let validEnvelope: SigilEnvelope = {
        SigilEnvelope(
            sigilID: "uid",
            vaultURL: "https://vw.obyw.one",
            tokenReference: "ref",
            expiresAt: Date(timeIntervalSince1970: 1_700_000_000 + 3600),
            hankoJWTProof: "p",
            machineIDEmitting: "A"
        )
    }()

    @Test("expired sigil → .sigilExpired")
    func expired() async {
        let now = Date(timeIntervalSince1970: 1_700_000_000 + 10_000)
        let exchange = HankoSigilExchange(
            broker: FakeHankoBroker(token: HankoMintedToken(token: "x", expiresAt: now, boundToMachineID: "B")),
            nowProvider: { now }
        )
        let outcome = await exchange.redeem(envelope: Self.validEnvelope, machineIDRedeeming: "B")
        #expect(outcome == .sigilExpired)
    }

    @Test("same-machine redemption refused")
    func sameMachine() async {
        let now = Date(timeIntervalSince1970: 1_700_000_000 + 60)
        let exchange = HankoSigilExchange(
            broker: FakeHankoBroker(token: HankoMintedToken(token: "x", expiresAt: now, boundToMachineID: "A")),
            nowProvider: { now }
        )
        let outcome = await exchange.redeem(envelope: Self.validEnvelope, machineIDRedeeming: "A")
        #expect(outcome == .sameMachineRefused)
    }

    @Test("happy redemption returns minted token within 5-min cap")
    func happy() async {
        let now = Date(timeIntervalSince1970: 1_700_000_000 + 60)
        let mintedExpiry = now.addingTimeInterval(180) // 3 min, within 5 min cap
        let mintedToken = HankoMintedToken(token: "t", expiresAt: mintedExpiry, boundToMachineID: "B")
        let exchange = HankoSigilExchange(
            broker: FakeHankoBroker(token: mintedToken),
            nowProvider: { now }
        )
        let outcome = await exchange.redeem(envelope: Self.validEnvelope, machineIDRedeeming: "B")
        if case .redeemed(let t) = outcome {
            #expect(t.token == "t")
            #expect(t.boundToMachineID == "B")
        } else { Issue.record("expected .redeemed, got \(outcome)") }
    }

    @Test("broker-returned 10-min TTL is rejected as TTL violation (T-W10-07 regression)")
    func brokerTTLViolation() async {
        let now = Date(timeIntervalSince1970: 1_700_000_000 + 60)
        let brokerExpiry = now.addingTimeInterval(600) // 10 min — exceeds 5 min cap
        let mintedToken = HankoMintedToken(token: "t", expiresAt: brokerExpiry, boundToMachineID: "B")
        let exchange = HankoSigilExchange(
            broker: FakeHankoBroker(token: mintedToken),
            nowProvider: { now }
        )
        let outcome = await exchange.redeem(envelope: Self.validEnvelope, machineIDRedeeming: "B")
        if case .brokerTTLViolation(let actual, let cap) = outcome {
            #expect(actual == brokerExpiry)
            #expect(cap == now.addingTimeInterval(300))
        } else { Issue.record("expected .brokerTTLViolation, got \(outcome)") }
    }

    @Test("machineID mismatch in minted token is rejected")
    func machineMismatch() async {
        let now = Date(timeIntervalSince1970: 1_700_000_000 + 60)
        let mintedToken = HankoMintedToken(token: "t", expiresAt: now.addingTimeInterval(60), boundToMachineID: "C")
        let exchange = HankoSigilExchange(
            broker: FakeHankoBroker(token: mintedToken),
            nowProvider: { now }
        )
        let outcome = await exchange.redeem(envelope: Self.validEnvelope, machineIDRedeeming: "B")
        if case .machineIDMismatch(let expected, let got) = outcome {
            #expect(expected == "B")
            #expect(got == "C")
        } else { Issue.record("expected .machineIDMismatch") }
    }

    @Test("broker error is surfaced as .brokerFailed")
    func brokerFails() async {
        let now = Date(timeIntervalSince1970: 1_700_000_000 + 60)
        let exchange = HankoSigilExchange(
            broker: FakeHankoBroker(error: FakeBrokerError()),
            nowProvider: { now }
        )
        let outcome = await exchange.redeem(envelope: Self.validEnvelope, machineIDRedeeming: "B")
        if case .brokerFailed = outcome { /* ok */ } else { Issue.record("expected .brokerFailed") }
    }
}
