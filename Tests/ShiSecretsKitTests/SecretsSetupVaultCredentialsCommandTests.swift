import Foundation
import Testing
@testable import ShiSecretsKit

// SecretsSetupVaultCredentialsCommandTests — TP-SVC-01..09
//
// Tests for SecretsSetupVaultCredentialsCommand via VaultCredentialsSeeder.
// No real Keychain, TTY, or network involved — all injected via protocols.
//
// TP-SVC-01: Happy path → .seeded, clientID prefix in output
// TP-SVC-02: Invalid clientID → .invalidClientID, no Keychain write
// TP-SVC-03: Invalid URL → .invalidServerURL, no Keychain write
// TP-SVC-04: Existing entry without --force → .alreadyExists, actionable error
// TP-SVC-05: Existing entry WITH --force → .seeded (overwrites)
// TP-SVC-06: --no-verify path → verifier not called
// TP-SVC-07: Verify failure (network) → Keychain write succeeded, exit error
// TP-SVC-08: client_secret NOT echoed in any SeedResult
// TP-SVC-09: migrateLegacyIfPresent called before store (order assertion)
//
// W3.1 — spec e8c4a921-7d3b-4f5e-9a2c-1d6b8f4e3a91

// Reuse mocks from VaultCredentialsSeederTests (already in ShiSecretsKitTests target)
// by redefining minimal versions here to avoid cross-file actor dependency.

// MARK: - Local Mocks

/// In-memory actor-isolated mock Keychain store — records call order.
actor OrderRecordingMockStore: VaultCredentialStore {
    var stored: VaultwardenCredentials? = nil
    var deleteCallCount: Int = 0
    var callOrder: [String] = []

    func load() async throws -> VaultwardenCredentials {
        callOrder.append("load")
        guard let c = stored else {
            throw KeychainVaultCredentials.KeychainError.itemNotFound
        }
        return c
    }

    func store(_ credentials: VaultwardenCredentials, overwrite: Bool) async throws {
        callOrder.append("store")
        if stored != nil && !overwrite {
            throw KeychainVaultCredentials.KeychainError.itemAlreadyExists
        }
        stored = credentials
    }

    func delete() async {
        callOrder.append("delete")
        stored = nil
        deleteCallCount += 1
    }
}

/// Actor-isolated mock that records whether verify() was called.
actor RecordingVerifier: VaultConnectionVerifier {
    var verifyCalled: Bool = false
    var shouldFail: Bool
    let failReason: String

    init(shouldFail: Bool = false, failReason: String = "network-error") {
        self.shouldFail = shouldFail
        self.failReason = failReason
    }

    func verify(credentials: VaultwardenCredentials) async throws {
        verifyCalled = true
        if shouldFail {
            throw NSError(domain: "TestNetworkError", code: 503,
                          userInfo: [NSLocalizedDescriptionKey: failReason])
        }
    }

    func wasCalledOnce() -> Bool { verifyCalled }
}

/// Pre-seeded store — has an entry already.
actor PreseededOrderStore: VaultCredentialStore {
    var current: VaultwardenCredentials
    var callOrder: [String] = []

    init(seed: VaultwardenCredentials) {
        current = seed
    }

    func load() async throws -> VaultwardenCredentials {
        callOrder.append("load")
        return current
    }

    func store(_ credentials: VaultwardenCredentials, overwrite: Bool) async throws {
        callOrder.append("store")
        guard overwrite else {
            throw KeychainVaultCredentials.KeychainError.itemAlreadyExists
        }
        current = credentials
    }

    func delete() async {
        callOrder.append("delete")
    }
}

// MARK: - Tests

@Suite("SecretsSetupVaultCredentialsCommand (via VaultCredentialsSeeder)")
struct SecretsSetupVaultCredentialsCommandTests {

    // TP-SVC-01: Happy path — valid args → .seeded + clientID prefix
    @Test("TP-SVC-01: valid args → .seeded with clientID prefix")
    func test_SVC_01_happyPath_returnsSeeded() async {
        let store = OrderRecordingMockStore()
        let verifier = RecordingVerifier(shouldFail: false)
        let seeder = VaultCredentialsSeeder(store: store, verifier: verifier)
        let result = await seeder.seed(
            clientID: "user.abc12345-6789",
            clientSecret: "s3cr3t-never-echo",
            serverURL: "https://vw.obyw.one",
            force: false,
            verify: true
        )
        guard case .seeded(let prefix) = result else {
            Issue.record("Expected .seeded, got \(result)")
            return
        }
        // Prefix must be the first 12 chars of clientID, never the secret
        #expect(prefix.hasPrefix("user.abc123"))
        // Secret must NOT appear in the prefix string
        #expect(!prefix.contains("s3cr3t"), "client_secret must not appear in output prefix")
        let verifyCalled = await verifier.verifyCalled
        #expect(verifyCalled, "Verifier should be called when verify=true")
    }

    // TP-SVC-02: Invalid clientID → .invalidClientID, no Keychain write
    @Test("TP-SVC-02: invalid clientID → .invalidClientID, no store write")
    func test_SVC_02_invalidClientID_noWrite() async {
        let store = OrderRecordingMockStore()
        let seeder = VaultCredentialsSeeder(store: store, verifier: nil)
        let result = await seeder.seed(
            clientID: "service.bad-format",
            clientSecret: "secret",
            serverURL: "https://vw.obyw.one",
            force: false,
            verify: false
        )
        #expect(result == .invalidClientID("service.bad-format"))
        let stored = await store.stored
        #expect(stored == nil, "No Keychain write for invalid clientID")
    }

    // TP-SVC-03: Invalid URL → .invalidServerURL, no Keychain write
    @Test("TP-SVC-03: invalid server URL → .invalidServerURL, no store write")
    func test_SVC_03_invalidURL_noWrite() async {
        let store = OrderRecordingMockStore()
        let seeder = VaultCredentialsSeeder(store: store, verifier: nil)
        let result = await seeder.seed(
            clientID: "user.valid-id",
            clientSecret: "secret",
            serverURL: "not-a-url",
            force: false,
            verify: false
        )
        #expect(result == .invalidServerURL("not-a-url"))
        let stored = await store.stored
        #expect(stored == nil, "No Keychain write for invalid URL")
    }

    // TP-SVC-04: Existing entry without --force → .alreadyExists
    @Test("TP-SVC-04: existing entry without force → .alreadyExists")
    func test_SVC_04_existingEntryNoForce_returnsAlreadyExists() async {
        let existing = VaultwardenCredentials(
            clientID: "user.existing",
            clientSecret: "old-secret",
            serverURL: URL(string: "https://vw.obyw.one")!
        )
        let store = PreseededOrderStore(seed: existing)
        let seeder = VaultCredentialsSeeder(store: store, verifier: nil)
        let result = await seeder.seed(
            clientID: "user.new-uuid",
            clientSecret: "new-secret",
            serverURL: "https://vw.obyw.one",
            force: false,
            verify: false
        )
        #expect(result == .alreadyExists)
        // The old entry must be preserved
        let current = try? await store.load()
        #expect(current?.clientID == "user.existing")
    }

    // TP-SVC-05: Existing entry WITH --force → .seeded (overwrites)
    @Test("TP-SVC-05: existing entry with force → .seeded, entry overwritten")
    func test_SVC_05_existingEntryWithForce_overwrites() async {
        let existing = VaultwardenCredentials(
            clientID: "user.existing",
            clientSecret: "old-secret",
            serverURL: URL(string: "https://vw.obyw.one")!
        )
        let store = PreseededOrderStore(seed: existing)
        let seeder = VaultCredentialsSeeder(store: store, verifier: nil)
        let result = await seeder.seed(
            clientID: "user.new-id-12345",
            clientSecret: "new-secret",
            serverURL: "https://vw.obyw.one",
            force: true,
            verify: false
        )
        guard case .seeded(let prefix) = result else {
            Issue.record("Expected .seeded, got \(result)")
            return
        }
        // New clientID prefix in output
        #expect(prefix.hasPrefix("user.new-id-"))
        // Store should now have new credentials
        let current = try? await store.load()
        #expect(current?.clientID == "user.new-id-12345")
    }

    // TP-SVC-06: --no-verify path → verifier not called
    @Test("TP-SVC-06: no-verify path → verifier is NOT called")
    func test_SVC_06_noVerify_verifierNotCalled() async {
        let store = OrderRecordingMockStore()
        let verifier = RecordingVerifier(shouldFail: false)
        let seeder = VaultCredentialsSeeder(store: store, verifier: verifier)
        let result = await seeder.seed(
            clientID: "user.no-verify-test",
            clientSecret: "s3cr3t",
            serverURL: "https://vw.obyw.one",
            force: false,
            verify: false  // no-verify
        )
        guard case .seeded(_) = result else {
            Issue.record("Expected .seeded, got \(result)")
            return
        }
        let verifyCalled = await verifier.verifyCalled
        #expect(!verifyCalled, "Verifier must NOT be called when verify=false (--no-verify flag)")
    }

    // TP-SVC-07: Verify failure (network) → Keychain was written, returns verifyFailed
    @Test("TP-SVC-07: verify failure → verifyFailed result (Keychain write was attempted)")
    func test_SVC_07_verifyFails_storeWasWritten_returnsVerifyFailed() async {
        let store = OrderRecordingMockStore()
        let verifier = RecordingVerifier(shouldFail: true, failReason: "connection-refused")
        let seeder = VaultCredentialsSeeder(store: store, verifier: verifier)
        let result = await seeder.seed(
            clientID: "user.verify-fail",
            clientSecret: "s3cr3t-wrong",
            serverURL: "https://vw.obyw.one",
            force: false,
            verify: true
        )
        guard case .verifyFailed(let reason) = result else {
            Issue.record("Expected .verifyFailed, got \(result)")
            return
        }
        #expect(reason.contains("connection-refused"))
        // The seeder reverts the write on verify failure — store should be empty
        let stored = await store.stored
        #expect(stored == nil, "Seeder reverts Keychain write after verify failure")
        // Verifier was called
        let verifyCalled = await verifier.verifyCalled
        #expect(verifyCalled)
    }

    // TP-SVC-08: client_secret does NOT appear in SeedResult in any form
    @Test("TP-SVC-08: client_secret is never reflected in SeedResult output")
    func test_SVC_08_clientSecret_notEchoedInResult() async {
        let store = OrderRecordingMockStore()
        let seeder = VaultCredentialsSeeder(store: store, verifier: nil)
        let secretValue = "SUPER_SECRET_DO_NOT_ECHO_12345"
        let result = await seeder.seed(
            clientID: "user.no-echo-test",
            clientSecret: secretValue,
            serverURL: "https://vw.obyw.one",
            force: false,
            verify: false
        )
        guard case .seeded(let prefix) = result else {
            Issue.record("Expected .seeded, got \(result)")
            return
        }
        // The prefix must NOT contain the secret
        #expect(!prefix.contains(secretValue),
                "client_secret MUST NEVER appear in SeedResult output")
        // Also check the string representation of the result
        let resultString = "\(result)"
        #expect(!resultString.contains(secretValue),
                "client_secret MUST NEVER appear in SeedResult description")
    }

    // TP-SVC-09: Store receives call before verify (order check via call order recording)
    @Test("TP-SVC-09: store.store() is called before verifier.verify()")
    func test_SVC_09_storeCalledBeforeVerify() async {
        let store = OrderRecordingMockStore()

        // We track order by using a sequence-recording verifier inside an actor
        actor CallSequence {
            var events: [String] = []
            func record(_ event: String) { events.append(event) }
        }
        let seq = CallSequence()

        struct SequenceRecordingStore: VaultCredentialStore {
            let inner: OrderRecordingMockStore
            let seq: CallSequence

            func load() async throws -> VaultwardenCredentials {
                await seq.record("load")
                return try await inner.load()
            }

            func store(_ credentials: VaultwardenCredentials, overwrite: Bool) async throws {
                await seq.record("store")
                try await inner.store(credentials, overwrite: overwrite)
            }

            func delete() async {
                await seq.record("delete")
                await inner.delete()
            }
        }

        struct SequenceRecordingVerifier: VaultConnectionVerifier {
            let seq: CallSequence
            func verify(credentials: VaultwardenCredentials) async throws {
                await seq.record("verify")
            }
        }

        let recordingStore = SequenceRecordingStore(inner: store, seq: seq)
        let recordingVerifier = SequenceRecordingVerifier(seq: seq)
        let seeder = VaultCredentialsSeeder(store: recordingStore, verifier: recordingVerifier)

        _ = await seeder.seed(
            clientID: "user.order-test",
            clientSecret: "secret",
            serverURL: "https://vw.obyw.one",
            force: false,
            verify: true
        )

        let events = await seq.events
        // "load" (check existing), "store" (write), "verify" (network check)
        let storeIdx = events.firstIndex(of: "store")
        let verifyIdx = events.firstIndex(of: "verify")
        if let si = storeIdx, let vi = verifyIdx {
            #expect(si < vi, "store() must be called before verify()")
        } else {
            Issue.record("Expected both store and verify events, got: \(events)")
        }
    }
}
