// SafetyFixV043RegressionTests — v0.4.3 deferred-safety fixes.

import Foundation
import Testing
@testable import ShiSecretsKit

@Suite("Safety fixes v0.4.3 — HIGH-2 / HIGH-4 / MED-6 / Sigil seal / Main.swift try? logging")
struct SafetyFixV0_4_3Tests {

    @Test("HIGH-2 SystemNameBindingVerifier: both absent → .ok(nil) (legacy install)")
    func bothAbsent() {
        let v = SystemNameBindingVerifier.verify(
            credentialsBoundName: nil, sidecarName: nil
        )
        #expect(v == .ok(systemName: nil))
    }

    @Test("HIGH-2 SystemNameBindingVerifier: sidecar present + Keychain absent → .ok(file) (legacy blob)")
    func keychainAbsentSidecarPresent() {
        let v = SystemNameBindingVerifier.verify(
            credentialsBoundName: nil, sidecarName: "mac-laptop"
        )
        #expect(v == .ok(systemName: "mac-laptop"))
    }

    @Test("HIGH-2 SystemNameBindingVerifier: Keychain bound + sidecar missing → .mismatch(.sidecarMissing)")
    func sidecarMissingButKeychainBound() {
        let v = SystemNameBindingVerifier.verify(
            credentialsBoundName: "mac-laptop", sidecarName: nil
        )
        if case .mismatch(let reason) = v {
            #expect(reason == .sidecarMissing)
        } else { Issue.record("expected .sidecarMissing") }
    }

    @Test("HIGH-2 SystemNameBindingVerifier: both present + match (case-insensitive) → .ok")
    func bothPresentMatch() {
        let v = SystemNameBindingVerifier.verify(
            credentialsBoundName: "Mac-Laptop", sidecarName: "mac-laptop"
        )
        #expect(v == .ok(systemName: "mac-laptop"))
    }

    @Test("HIGH-2 SystemNameBindingVerifier: both present + diverge → .mismatch(.fileDoesNotMatchKeychain)")
    func bothPresentDiverge() {
        let v = SystemNameBindingVerifier.verify(
            credentialsBoundName: "mac-laptop", sidecarName: "evil-other"
        )
        if case .mismatch(let reason) = v {
            if case .fileDoesNotMatchKeychain(let f, let k) = reason {
                #expect(f == "evil-other")
                #expect(k == "mac-laptop")
            } else { Issue.record("expected fileDoesNotMatchKeychain") }
        } else { Issue.record("expected mismatch") }
    }

    @Test("HIGH-2 SystemNameBindingVerifier: MismatchReason.operatorMessage gives actionable guidance")
    func mismatchMessages() {
        #expect(SystemNameBindingVerifier.MismatchReason.sidecarMissing.operatorMessage.contains("wizard"))
        let div = SystemNameBindingVerifier.MismatchReason.fileDoesNotMatchKeychain(fromFile: "a", fromKeychain: "b")
        #expect(div.operatorMessage.contains("cache-poisoning"))
    }

    @Test("VaultwardenCredentials encodes/decodes boundSystemName as snake_case")
    func credentialsBoundNameRoundTrip() throws {
        let creds = VaultwardenCredentials(
            clientID: "user.abc", clientSecret: "x",
            serverURL: URL(string: "https://vw.obyw.one")!,
            boundSystemName: "mac-laptop-shikki"
        )
        let data = try JSONEncoder().encode(creds)
        let json = String(data: data, encoding: .utf8) ?? ""
        #expect(json.contains("\"bound_system_name\""))
        #expect(json.contains("mac-laptop-shikki"))

        let decoded = try JSONDecoder().decode(VaultwardenCredentials.self, from: data)
        #expect(decoded.boundSystemName == "mac-laptop-shikki")
    }

    @Test("VaultwardenCredentials legacy blob without boundSystemName decodes OK")
    func credentialsLegacyBlob() throws {
        let legacyJSON = """
        {"client_id":"user.legacy","client_secret":"old","server_url":"https://vw.obyw.one"}
        """
        let creds = try JSONDecoder().decode(
            VaultwardenCredentials.self,
            from: legacyJSON.data(using: .utf8)!
        )
        #expect(creds.boundSystemName == nil)
        #expect(creds.clientID == "user.legacy")
    }

    @Test("Sigil seal: SigilEnvelope.signed factory enforces 300s cap")
    func sigilFactoryCapEnforced() {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let env = SigilEnvelope.signed(
            at: now,
            vaultURL: "https://x", tokenReference: "r", hankoJWTProof: "p",
            machineIDEmitting: "A",
            ttlSeconds: 86400 // 1 day requested
        )
        #expect(env.expiresAt == now.addingTimeInterval(300))
    }

    @Test("Sigil seal: SigilEnvelope.signed factory accepts < cap TTL verbatim")
    func sigilFactoryShortTTL() {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let env = SigilEnvelope.signed(
            at: now,
            vaultURL: "https://x", tokenReference: "r", hankoJWTProof: "p",
            machineIDEmitting: "A", ttlSeconds: 60
        )
        #expect(env.expiresAt == now.addingTimeInterval(60))
    }
}
