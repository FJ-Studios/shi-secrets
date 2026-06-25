// ScopePolicyTests — TP-W6.5c-09 / TP-W6.5c-10 / TP-W6.5c-11.
//
// Wire-enforced "this system reads ONLY shi/system/<self> + shi/shared" check.
// Mapping to spec test IDs:
//   T-W6.5c-09 → systemReadsOnly_collection_shi_system_self_AND_shi_shared
//   T-W6.5c-10 → systemCANNOT_readOtherSystemsCollections
//   T-W6.5c-11 → systemCANNOT_readOperatorPersonalVault

import Foundation
import Testing
@testable import ShiSecretsKit

@Suite("W6.5c ScopePolicy — allowed reads")
struct ScopePolicyAllowedTests {

    @Test("self-scope path is allowed")
    func selfScopeAllowed() {
        let p = ScopePolicy(systemName: "mac-laptop-shikki")
        let d = p.decide("shi/system/mac-laptop-shikki/openai-api-key")
        #expect(d.isAllowed)
        if case .allowed(let rule) = d { #expect(rule == .selfScope) }
    }

    @Test("self-scope root prefix is allowed")
    func selfScopeRootAllowed() {
        let p = ScopePolicy(systemName: "mac-laptop-shikki")
        #expect(p.canRead(path: "shi/system/mac-laptop-shikki"))
    }

    @Test("shared bucket is allowed")
    func sharedBucketAllowed() {
        let p = ScopePolicy(systemName: "mac-laptop-shikki")
        let d = p.decide("shi/shared/common-vw-server")
        #expect(d.isAllowed)
        if case .allowed(let rule) = d { #expect(rule == .sharedScope) }
    }
}

@Suite("W6.5c ScopePolicy — blast-radius isolation")
struct ScopePolicyDeniedTests {

    @Test("OTHER system's scope is denied (blast-radius isolation)")
    func otherSystemDenied() {
        let p = ScopePolicy(systemName: "mac-laptop-shikki")
        let d = p.decide("shi/system/nuc-dev-shikki/openai-api-key")
        #expect(!d.isAllowed)
        if case .denied(let reason) = d {
            #expect(reason == .otherSystemScope)
        } else { Issue.record("expected denied with otherSystemScope") }
    }

    @Test("operator personal vault is denied (broker never sees it)")
    func personalVaultDenied() {
        let p = ScopePolicy(systemName: "mac-laptop-shikki")
        let d = p.decide("shi/personal/master-bitwarden-key")
        #expect(!d.isAllowed)
        if case .denied(let reason) = d {
            #expect(reason == .personalVault)
        } else { Issue.record("expected denied with personalVault") }
    }

    @Test("paths outside shi/ are denied default-closed")
    func defaultClosed() {
        let p = ScopePolicy(systemName: "mac-laptop-shikki")
        let d = p.decide("random/foo")
        #expect(!d.isAllowed)
        if case .denied(let reason) = d {
            #expect(reason == .outsideAllowedScopes)
        } else { Issue.record("expected outsideAllowedScopes") }
    }

    @Test("empty path is denied with clear reason")
    func emptyPathDenied() {
        let p = ScopePolicy(systemName: "mac-laptop-shikki")
        if case .denied(let reason) = p.decide("") {
            #expect(reason == .emptyPath)
        } else { Issue.record("expected emptyPath") }
    }

    @Test("DenyReason carries an operator-facing message")
    func denyReasonMessages() {
        #expect(ScopePolicy.DenyReason.otherSystemScope.operatorMessage.contains("blast-radius"))
        #expect(ScopePolicy.DenyReason.personalVault.operatorMessage.contains("operator"))
    }
}
