import Crypto
import Foundation
@testable import ShiSecretsBrokerd
import ShiSecretsKit

// Shared test helpers for the brokerd-target suites.
//
// W1 change (shi-secrets W1 — 2026-05-21):
//   - StubBootstrapProvider updated: unseal() is now async and returns
//     (vaultClient: VaultwardenClient, signingKey: BrokerSigningKey).
//   - FakeProcessHandle / FakeProcessLauncher removed — bw CLI subprocess
//     pattern is gone. Use InMemoryBWClient.activate() + seedFakeEntry() instead.

/// A BootstrapProvider stub that either returns a deterministic pair or
/// throws. Review finding U13 — lets tests drive the daemon's unseal
/// refusal path without touching the Keychain.
public struct StubBootstrapProvider: BootstrapProvider {
    public enum Behavior: Sendable {
        case succeed
        case fail(BootstrapError)
    }
    public let behavior: Behavior
    public init(behavior: Behavior = .succeed) {
        self.behavior = behavior
    }
    public func unseal() async throws -> (vaultClient: VaultwardenClient, signingKey: BrokerSigningKey) {
        switch behavior {
        case .succeed:
            let creds = VaultwardenCredentials(
                clientID: "user.stub",
                clientSecret: "stub-secret",
                serverURL: URL(string: "https://vw.obyw.one")!
            )
            let client = try VaultwardenClient(
                credentials: creds,
                configYmlVaultServer: "https://vw.obyw.one"
            )
            let key = Curve25519.Signing.PrivateKey()
            return (client, BrokerSigningKey(privateKey: key))
        case .fail(let err):
            throw err
        }
    }
}

// FakeProcessHandle / FakeProcessLauncher REMOVED in W1.
// The bw CLI subprocess pattern is gone — no process spawn exists in the broker.
// Tests that previously used these fakes should use InMemoryBWClient instead:
//   let client = InMemoryBWClient()
//   await client.activate()
//   await client.seedFakeEntry(name: "...", fields: [...])
