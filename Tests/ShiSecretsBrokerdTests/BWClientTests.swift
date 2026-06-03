import Foundation
@testable import ShiSecretsBrokerd
import ShiSecretsKit
import Testing

// BWClientTests — updated for W1 (shi-secrets W1 — 2026-05-21).
//
// The bw CLI subprocess launch path has been removed. InMemoryBWClient
// no longer takes a ProcessLauncher; it is activated via activate() and
// driven via seedFakeEntry(). All tests updated accordingly.

@Suite("BWClient")
struct BWClientTests {

    // MARK: - InMemoryBWClient (fake / test path)

    @Test("W1: InMemoryBWClient — activate() + seedFakeEntry + get() returns seeded fields")
    func test_bwClient_get_secretByName_returnsPlaintext() async throws {
        let client = InMemoryBWClient()
        await client.activate()
        await client.seedFakeEntry(name: "OVH_APP_KEY", fields: ["applicationKey": "ak-1"])

        let fields = try await client.get(name: "OVH_APP_KEY")

        #expect(fields["applicationKey"] == "ak-1")
    }

    @Test("W1: InMemoryBWClient — update persists fields visible on subsequent get")
    func test_bwClient_update_secretByName_persistsToFakeVault() async throws {
        let client = InMemoryBWClient()
        await client.activate()
        try await client.update(name: "BREVO_API_KEY", fields: ["apiKey": "new-key"])

        let fields = try await client.get(name: "BREVO_API_KEY")

        #expect(fields["apiKey"] == "new-key")
    }

    @Test("W1: InMemoryBWClient — invalidateSession disables further get/update calls")
    func test_bwClient_invalidateSession_disablesFurtherCalls() async throws {
        let client = InMemoryBWClient()
        await client.activate()

        await client.invalidateSession()

        do {
            _ = try await client.get(name: "anything")
            Issue.record("expected BWClientError.sessionInvalidated")
        } catch let error as BWClientError {
            #expect(error == .sessionInvalidated)
        }
    }

    @Test("W1: InMemoryBWClient — no BW_SESSION env var path exists")
    func test_bwClient_noBWSessionEnvVar() async {
        // Structural test: InMemoryBWClient.activate() takes no String argument.
        // There is no BW_SESSION env var path in the W1 implementation.
        let client = InMemoryBWClient()
        await client.activate()
        let valid = await client.isSessionValid
        #expect(valid == true, "activate() makes session valid without any env var")
    }

    // MARK: - ProductionBWClient

    @Test("ProductionBWClient — invalidateSession bumps session epoch monotonically (I1)")
    func test_productionBWClient_invalidateSession_bumpsEpoch() async {
        // 3rd-pass validator I1 — epoch plumbing is real mutable state.
        let prod = ProductionBWClient()
        let e0 = await prod.sessionEpoch
        #expect(e0 == 0)

        await prod.invalidateSession()
        let e1 = await prod.sessionEpoch
        #expect(e1 == 1)

        for _ in 0 ..< 9 {
            await prod.invalidateSession()
        }
        let e10 = await prod.sessionEpoch
        #expect(e10 == 10)
    }

    @Test("ProductionBWClient — isSessionValid is false until wire(client:) called")
    func test_productionBWClient_sessionInvalidUntilWired() async {
        let prod = ProductionBWClient()
        let valid = await prod.isSessionValid
        #expect(valid == false, "Session invalid until wire(client:) called")
    }

    @Test("ProductionBWClient — update without session throws sessionInvalidated (W3: wired, not stub)")
    func test_productionBWClient_update_withoutSession_throwsSessionInvalidated() async {
        // W3: update() now calls set() internally. Without a wired session,
        // it throws sessionInvalidated — not the old notImplementedV1_1 stub.
        let prod = ProductionBWClient()
        // Do NOT wire — session stays invalid.
        await #expect(throws: BWClientError.sessionInvalidated) {
            try await prod.update(name: "x", fields: ["k": "v"])
        }
    }

    @Test("W3: InMemoryBWClient — set + get round-trip stores and retrieves value")
    func test_inMemoryBWClient_set_getReturnsValue() async throws {
        let client = InMemoryBWClient()
        await client.activate()
        try await client.set(name: "ci-token", value: "secret-abc")
        let fields = try await client.get(name: "ci-token")
        #expect(fields["value"] == "secret-abc")
    }

    @Test("W3: InMemoryBWClient — set + list includes name")
    func test_inMemoryBWClient_set_listIncludesName() async throws {
        let client = InMemoryBWClient()
        await client.activate()
        try await client.set(name: "my-key", value: "my-value")
        let names = try await client.list()
        #expect(names.contains("my-key"))
    }

    @Test("W3: InMemoryBWClient — set + delete removes name from list")
    func test_inMemoryBWClient_set_delete_removedFromList() async throws {
        let client = InMemoryBWClient()
        await client.activate()
        try await client.set(name: "temp-key", value: "v")
        try await client.delete(name: "temp-key")
        let names = try await client.list()
        #expect(!names.contains("temp-key"))
    }

    // MARK: - Helpers

    private func dummyVaultwardenClient() throws -> VaultwardenClient {
        let creds = VaultwardenCredentials(
            clientID: "user.test",
            clientSecret: "s",
            serverURL: URL(string: "https://vw.obyw.one")!
        )
        return try VaultwardenClient(credentials: creds, configYmlVaultServer: "https://vw.obyw.one")
    }
}
