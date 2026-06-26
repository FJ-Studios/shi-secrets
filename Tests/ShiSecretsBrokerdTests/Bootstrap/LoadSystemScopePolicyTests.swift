// LoadSystemScopePolicyTests — v0.5.0 Wave A1 regression guard.

import Foundation
import Testing
@testable import ShiSecretsBrokerd
@testable import ShiSecretsKit

@Suite("Wave A1 — loadSystemScopePolicy()")
struct LoadSystemScopePolicyTests {

    @Test("AC-A1-01: protocol default returns nil (test double convenience)")
    func protocolDefaultIsNil() throws {
        struct NoopProvider: BootstrapProvider {
            func unseal() async throws -> (vaultClient: VaultwardenClient, signingKey: BrokerSigningKey) {
                throw BootstrapError.keychainCredentialsMissing
            }
        }
        let p = NoopProvider()
        let policy = try p.loadSystemScopePolicy()
        #expect(policy == nil)
    }

    @Test("AC-A1-02: SystemScopePolicyLoadError.bindingMismatch carries reason")
    func bindingMismatchHasReason() {
        let e = SystemScopePolicyLoadError.bindingMismatch(reason: "test-reason")
        if case .bindingMismatch(let r) = e {
            #expect(r == "test-reason")
        } else { Issue.record("expected .bindingMismatch") }
    }

    @Test("AC-A1-02: SystemScopePolicyLoadError.sidecarReadFailed carries reason")
    func sidecarReadFailedHasReason() {
        let e = SystemScopePolicyLoadError.sidecarReadFailed(reason: "permission-denied")
        if case .sidecarReadFailed(let r) = e {
            #expect(r == "permission-denied")
        } else { Issue.record("expected .sidecarReadFailed") }
    }

    @Test("AC-A1-03: provider override returns a real policy without touching FS")
    func providerCanOverride() throws {
        struct MockWithPolicy: BootstrapProvider {
            func unseal() async throws -> (vaultClient: VaultwardenClient, signingKey: BrokerSigningKey) {
                throw BootstrapError.keychainCredentialsMissing
            }
            func loadSystemScopePolicy() throws -> ScopePolicy? {
                return ScopePolicy(systemName: "mock-system")
            }
        }
        let p = MockWithPolicy()
        let policy = try p.loadSystemScopePolicy()
        #expect(policy != nil)
        #expect(policy?.systemName == "mock-system")
    }

    @Test("AC-A1-03: provider override can throw bindingMismatch")
    func providerCanThrowBindingMismatch() {
        struct MockMismatch: BootstrapProvider {
            func unseal() async throws -> (vaultClient: VaultwardenClient, signingKey: BrokerSigningKey) {
                throw BootstrapError.keychainCredentialsMissing
            }
            func loadSystemScopePolicy() throws -> ScopePolicy? {
                throw SystemScopePolicyLoadError.bindingMismatch(reason: "sidecar=foo, keychain=bar")
            }
        }
        do {
            _ = try MockMismatch().loadSystemScopePolicy()
            Issue.record("expected throw")
        } catch SystemScopePolicyLoadError.bindingMismatch {
            // ok
        } catch {
            Issue.record("expected bindingMismatch, got \(error)")
        }
    }
}
