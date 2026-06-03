import Foundation
@testable import ShiSecretsKit
import Testing

// VaultCredentialsSeederTests — TP-VC-01..07
//
// Tests exercise VaultCredentialsSeeder with injected mock store + verifier so
// no real Keychain entries are touched. All state mutations are actor-isolated.
//
// TP-VC-01: Missing clientID (empty string) → .invalidClientID
// TP-VC-02: All valid args → writes to store → read-back round-trip OK
// TP-VC-03: Empty clientSecret is passed through (CLI layer guards; seeder writes)
// TP-VC-04: Existing entry + !force → returns .alreadyExists
// TP-VC-05: clientID doesn't start with "user." → returns .invalidClientID
// TP-VC-06: serverURL malformed → returns .invalidServerURL
// TP-VC-07: verify fails → reverts write, returns .verifyFailed

// MARK: - Mocks

/// In-memory actor-isolated mock Keychain store.
actor MockVaultCredentialStore: VaultCredentialStore {
    var stored: VaultwardenCredentials? = nil
    var deleteCallCount: Int = 0

    func load() async throws -> VaultwardenCredentials {
        guard let c = stored else {
            throw KeychainVaultCredentials.KeychainError.itemNotFound
        }
        return c
    }

    func store(_ credentials: VaultwardenCredentials, overwrite: Bool) async throws {
        if stored != nil && !overwrite {
            throw KeychainVaultCredentials.KeychainError.itemAlreadyExists
        }
        stored = credentials
    }

    func delete() async {
        stored = nil
        deleteCallCount += 1
    }
}

/// In-memory actor-isolated mock that starts with a pre-seeded entry.
actor PreseededMockStore: VaultCredentialStore {
    var current: VaultwardenCredentials

    init(seed: VaultwardenCredentials) {
        current = seed
    }

    func load() async throws -> VaultwardenCredentials { current }

    func store(_ credentials: VaultwardenCredentials, overwrite: Bool) async throws {
        guard overwrite else {
            throw KeychainVaultCredentials.KeychainError.itemAlreadyExists
        }
        current = credentials
    }

    func delete() async {
        // For test read-back after verify-failure revert, reset to
        // original seed would be needed, but seeder calls delete after store,
        // so we just nil out (use MockVaultCredentialStore for that path).
    }
}

/// Verifier that always succeeds.
struct SucceedingVerifier: VaultConnectionVerifier, Sendable {
    func verify(credentials: VaultwardenCredentials) async throws { /* no-op */ }
}

/// Verifier that always fails with the given message.
struct FailingVerifier: VaultConnectionVerifier, Sendable {
    let reason: String
    func verify(credentials: VaultwardenCredentials) async throws {
        throw NSError(domain: "TestError", code: 1, userInfo: [NSLocalizedDescriptionKey: reason])
    }
}

// MARK: - Tests

@Suite("VaultCredentialsSeeder")
struct VaultCredentialsSeederTests {

    // TP-VC-01: Empty clientID → .invalidClientID, nothing written
    @Test("TP-VC-01: empty clientID returns invalidClientID without writing")
    func test_VC_01_emptyClientID_returnsInvalidClientID() async {
        let store = MockVaultCredentialStore()
        let seeder = VaultCredentialsSeeder(store: store, verifier: nil)
        let result = await seeder.seed(
            clientID: "",
            clientSecret: "secret",
            serverURL: "https://vw.obyw.one",
            force: false,
            verify: false
        )
        #expect(result == .invalidClientID(""))
        let stored = await store.stored
        #expect(stored == nil, "Nothing should be written when clientID is invalid")
    }

    // TP-VC-02: All valid args → writes to store → read-back round-trip OK
    @Test("TP-VC-02: valid args write to store and round-trip matches")
    func test_VC_02_validArgs_writesAndRoundTrips() async {
        let store = MockVaultCredentialStore()
        let seeder = VaultCredentialsSeeder(store: store, verifier: SucceedingVerifier())
        let result = await seeder.seed(
            clientID: "user.test-uuid-1234",
            clientSecret: "s3cr3t-value",
            serverURL: "https://vw.obyw.one",
            force: false,
            verify: true
        )
        guard case .seeded(let prefix) = result else {
            Issue.record("Expected .seeded, got \(result)")
            return
        }
        #expect(prefix.hasPrefix("user.test-uu"))
        let stored = await store.stored
        #expect(stored?.clientID == "user.test-uuid-1234")
        #expect(stored?.serverURL == URL(string: "https://vw.obyw.one"))
        // clientSecret stored but NEVER printed — we verify the round-trip only
        #expect(stored?.clientSecret == "s3cr3t-value")
    }

    // TP-VC-03: No-verify path writes without touching verifier
    @Test("TP-VC-03: no-verify path writes without calling verifier")
    func test_VC_03_noVerify_writesWithoutCallingVerifier() async {
        let store = MockVaultCredentialStore()
        // Pass a failing verifier — if it's called the test fails via store being nil
        let failVerifier = FailingVerifier(reason: "should-not-be-called")
        let seeder = VaultCredentialsSeeder(store: store, verifier: failVerifier)
        let result = await seeder.seed(
            clientID: "user.abc-def",
            clientSecret: "secret-val",
            serverURL: "https://vw.obyw.one",
            force: false,
            verify: false  // <-- no verify
        )
        guard case .seeded(_) = result else {
            Issue.record("Expected .seeded, got \(result)")
            return
        }
        let stored = await store.stored
        #expect(stored != nil, "Entry should be written even without verify")
    }

    // TP-VC-04: Existing entry + !force → .alreadyExists, original preserved
    @Test("TP-VC-04: existing entry without force returns alreadyExists")
    func test_VC_04_existingEntryNoForce_returnsAlreadyExists() async {
        let existing = VaultwardenCredentials(
            clientID: "user.existing",
            clientSecret: "old-secret",
            serverURL: URL(string: "https://vw.obyw.one")!
        )
        let store = PreseededMockStore(seed: existing)
        let seeder = VaultCredentialsSeeder(store: store, verifier: nil)
        let result = await seeder.seed(
            clientID: "user.new-uuid",
            clientSecret: "new-secret",
            serverURL: "https://vw.obyw.one",
            force: false,
            verify: false
        )
        #expect(result == .alreadyExists)
        // Old entry must be preserved
        let current = try? await store.load()
        #expect(current?.clientID == "user.existing")
    }

    // TP-VC-05: clientID not starting with "user." → .invalidClientID
    @Test("TP-VC-05: clientID not starting with 'user.' returns invalidClientID")
    func test_VC_05_badClientIDFormat_returnsInvalidClientID() async {
        let store = MockVaultCredentialStore()
        let seeder = VaultCredentialsSeeder(store: store, verifier: nil)
        let badID = "service.abc-123"
        let result = await seeder.seed(
            clientID: badID,
            clientSecret: "secret",
            serverURL: "https://vw.obyw.one",
            force: false,
            verify: false
        )
        #expect(result == .invalidClientID(badID))
        let stored = await store.stored
        #expect(stored == nil, "Nothing should be written for invalid clientID format")
    }

    // TP-VC-06: Malformed serverURL → .invalidServerURL
    @Test("TP-VC-06: malformed serverURL returns invalidServerURL")
    func test_VC_06_malformedServerURL_returnsInvalidServerURL() async {
        let store = MockVaultCredentialStore()
        let seeder = VaultCredentialsSeeder(store: store, verifier: nil)
        let badURL = "not-a-url"
        let result = await seeder.seed(
            clientID: "user.test",
            clientSecret: "secret",
            serverURL: badURL,
            force: false,
            verify: false
        )
        #expect(result == .invalidServerURL(badURL))
        let stored = await store.stored
        #expect(stored == nil, "Nothing should be written for invalid URL")
    }

    // TP-VC-07: Verify fails → reverts write → .verifyFailed
    @Test("TP-VC-07: verify failure reverts write and returns verifyFailed")
    func test_VC_07_verifyFail_revertsWriteAndReturnsVerifyFailed() async {
        let store = MockVaultCredentialStore()
        let verifier = FailingVerifier(reason: "token_grant_401")
        let seeder = VaultCredentialsSeeder(store: store, verifier: verifier)
        let result = await seeder.seed(
            clientID: "user.test-verify",
            clientSecret: "wrong-secret",
            serverURL: "https://vw.obyw.one",
            force: false,
            verify: true
        )
        guard case .verifyFailed(let reason) = result else {
            Issue.record("Expected .verifyFailed, got \(result)")
            return
        }
        #expect(reason.contains("token_grant_401"))
        // Write must have been reverted
        let stored = await store.stored
        #expect(stored == nil, "Keychain entry should be reverted after verify failure")
        let delCount = await store.deleteCallCount
        #expect(delCount == 1, "delete() must be called exactly once on verify failure")
    }
}
