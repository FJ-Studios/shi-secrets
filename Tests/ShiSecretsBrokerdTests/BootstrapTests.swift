import Crypto
import Foundation
@testable import ShiSecretsBrokerd
import ShiSecretsKit
import Testing

// Bootstrap unit tests — W1 (shi-secrets W1 — 2026-05-21)
//
// Updated for the Keychain + VaultwardenClient bootstrap path.
// The old systemd CREDENTIALS_DIRECTORY / BW_SESSION path is gone.
//
// Tests verify:
//   - Bootstrap conforms to BootstrapProvider (async unseal).
//   - BootstrapError carries the right types for Keychain failures.
//   - v12UpgradePathDocumentation string documents the Keychain path.
//   - StubBootstrapProvider covers the inject-for-test pattern.

@Suite("Bootstrap (W1 — Keychain + VaultwardenClient)")
struct BootstrapTests {

    // MARK: - BootstrapError cases

    @Test("BootstrapError.keychainCredentialsMissing is distinct from vaultwardenConnectFailed")
    func test_bootstrapError_keychainMissingVsConnectFailed() {
        let a = BootstrapError.keychainCredentialsMissing
        let b = BootstrapError.vaultwardenConnectFailed(message: "conn refused")
        #expect(a != b)
    }

    @Test("BootstrapError.keychainOSError carries OSStatus code")
    func test_bootstrapError_keychainOSError_carriesStatus() {
        let err = BootstrapError.keychainOSError(status: -25300)
        if case .keychainOSError(let status) = err {
            #expect(status == -25300)
        } else {
            Issue.record("keychainOSError case not matched")
        }
    }

    @Test("BootstrapError.vaultwardenConnectFailed carries message string")
    func test_bootstrapError_connectFailed_carriesMessage() {
        let msg = "network unreachable"
        let err = BootstrapError.vaultwardenConnectFailed(message: msg)
        if case .vaultwardenConnectFailed(let m) = err {
            #expect(m == msg)
        } else {
            Issue.record("vaultwardenConnectFailed case not matched")
        }
    }

    // MARK: - Deprecated shims redirect to keychainCredentialsMissing

    @Test("Deprecated .credentialsDirectoryMissing redirects to keychainCredentialsMissing")
    func test_deprecatedShim_credentialsDirectoryMissing() {
        let err = BootstrapError.credentialsDirectoryMissing
        #expect(err == .keychainCredentialsMissing, "Deprecated shim == keychainCredentialsMissing")
    }

    @Test("Deprecated .bwSessionEmpty redirects to keychainCredentialsMissing")
    func test_deprecatedShim_bwSessionEmpty() {
        let err = BootstrapError.bwSessionEmpty
        #expect(err == .keychainCredentialsMissing, "Deprecated shim == keychainCredentialsMissing")
    }

    // MARK: - v12 documentation string

    @Test("v12UpgradePathDocumentation mentions Keychain and W1")
    func test_v12UpgradePath_mentionsKeychainAndW1() {
        let doc = Bootstrap.v12UpgradePathDocumentation
        #expect(doc.contains("Keychain") || doc.contains("keychain"),
                "v12 doc must mention Keychain")
        #expect(doc.contains("W1") || doc.contains("Wave 1") || doc.contains("v1"),
                "v12 doc must mention wave/version")
    }

    // MARK: - BootstrapProvider conformance (via stub)

    @Test("StubBootstrapProvider conforms to BootstrapProvider — unseal() is async")
    func test_stubBootstrapProvider_conformsToProtocol() async throws {
        // Verify the injection-point pattern works end-to-end with the stub.
        let provider: any BootstrapProvider = StubBootstrapProvider()
        let (client, signingKey) = try await provider.unseal()
        _ = client
        _ = signingKey
        #expect(Bool(true), "StubBootstrapProvider.unseal() returns without throwing")
    }

    @Test("StubBootstrapProvider(behavior: .fail(.keychainCredentialsMissing)) throws correctly")
    func test_stubBootstrapProvider_fail_keychainMissing() async {
        let provider: any BootstrapProvider = StubBootstrapProvider(behavior: .fail(.keychainCredentialsMissing))
        await #expect(throws: BootstrapError.keychainCredentialsMissing) {
            _ = try await provider.unseal()
        }
    }

    // MARK: - BrokerMain refuse-to-start gate

    @Test("Bootstrap conforms to BootstrapProvider — production type is the injection point")
    func test_bootstrap_conformsToBootstrapProvider() {
        // Type-system assertion: Bootstrap is assignable to any BootstrapProvider.
        // Cannot call live Bootstrap.unseal() in unit tests (requires Keychain).
        let _: any BootstrapProvider = Bootstrap()
        #expect(Bool(true), "Bootstrap: any BootstrapProvider compiles — conformance verified")
    }
}
