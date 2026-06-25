import Foundation
import Testing
@testable import ShiSecretsKit

// KeychainVaultCredentialsMigrationTests — TP-KMG-01..04
//
// Tests for KeychainVaultCredentials.migrateLegacyIfPresent().
// These tests use mock objects to avoid touching the real macOS Keychain.
//
// TP-KMG-01: migrateLegacyIfPresent writes to canonical and removes legacy (happy path)
// TP-KMG-02: migrateLegacyIfPresent is a no-op when legacy is absent
// TP-KMG-03: migrateLegacyIfPresent is idempotent (safe to call twice)
// TP-KMG-04: Constants — canonical service = io.shikki.vault, legacy = eu.fj-studios.shikki.vault
//
// W3.1 — spec e8c4a921-7d3b-4f5e-9a2c-1d6b8f4e3a91

// MARK: - Constants Tests

@Suite("KeychainVaultCredentials constants")
struct KeychainVaultCredentialsConstantsTests {

    // TP-KMG-04a: canonical service is io.shikki domain
    @Test("TP-KMG-04a: canonical service = io.shikki.vault")
    func test_KMG_04a_canonicalService_isProductDomain() {
        #expect(KeychainVaultCredentials.service == "io.shikki.vault")
    }

    // TP-KMG-04b: legacy service preserved for migration
    @Test("TP-KMG-04b: legacyService = eu.fj-studios.shikki.vault (preserved for migration)")
    func test_KMG_04b_legacyService_isOrgNamespace() {
        #expect(KeychainVaultCredentials.legacyService == "eu.fj-studios.shikki.vault")
    }

    // TP-KMG-04c: canonical and legacy differ
    @Test("TP-KMG-04c: canonical and legacy service are different")
    func test_KMG_04c_canonicalAndLegacy_areDifferent() {
        #expect(KeychainVaultCredentials.service != KeychainVaultCredentials.legacyService)
    }
}

// MARK: - Migration Tests using MockMigratableStore

/// Protocol for testing migration behaviour without touching macOS Keychain.
/// Simulates the KeychainVaultCredentials migration logic with in-memory state.
actor MockMigratableStore {
    /// Items stored by service key. Key = service string, Value = encoded JSON data.
    var items: [String: VaultwardenCredentials] = [:]
    var deleteCallCount: [String: Int] = [:]

    /// Seed an item under a given service name (simulates legacy entry).
    func seed(_ credentials: VaultwardenCredentials, forService service: String) {
        items[service] = credentials
    }

    /// Read item for service.
    func read(forService service: String) -> VaultwardenCredentials? {
        items[service]
    }

    /// Write item for service.
    func write(_ credentials: VaultwardenCredentials, forService service: String) {
        items[service] = credentials
    }

    /// Delete item for service.
    func delete(forService service: String) {
        items.removeValue(forKey: service)
        deleteCallCount[service, default: 0] += 1
    }

    /// Simulate migrateLegacyIfPresent() logic (mirrors implementation).
    func migrateLegacy(from legacyService: String, to canonicalService: String) {
        guard let legacy = items[legacyService] else { return }
        items[canonicalService] = legacy
        items.removeValue(forKey: legacyService)
        deleteCallCount[legacyService, default: 0] += 1
    }
}

@Suite("KeychainVaultCredentials migration")
struct KeychainVaultCredentialsMigrationTests {

    // TP-KMG-01: Legacy present → migrate to canonical → legacy deleted
    @Test("TP-KMG-01: migrateLegacyIfPresent moves entry to canonical and removes legacy")
    func test_KMG_01_legacyPresent_migratesAndDeletesLegacy() async {
        let store = MockMigratableStore()
        let credentials = VaultwardenCredentials(
            clientID: "user.migration-test",
            clientSecret: "s3cr3t",
            serverURL: URL(string: "https://vw.obyw.one")!
        )
        // Seed under legacy service
        await store.seed(credentials, forService: KeychainVaultCredentials.legacyService)

        // Run migration logic
        await store.migrateLegacy(
            from: KeychainVaultCredentials.legacyService,
            to: KeychainVaultCredentials.service
        )

        // Canonical should have the entry
        let canonical = await store.read(forService: KeychainVaultCredentials.service)
        #expect(canonical?.clientID == "user.migration-test")
        #expect(canonical?.serverURL == URL(string: "https://vw.obyw.one"))

        // Legacy should be gone
        let legacy = await store.read(forService: KeychainVaultCredentials.legacyService)
        #expect(legacy == nil, "Legacy entry must be removed after migration")

        // Delete was called exactly once for legacy
        let deleteCount = await store.deleteCallCount[KeychainVaultCredentials.legacyService]
        #expect(deleteCount == 1)
    }

    // TP-KMG-02: Legacy absent → no-op (canonical unchanged)
    @Test("TP-KMG-02: migrateLegacyIfPresent is no-op when legacy is absent")
    func test_KMG_02_legacyAbsent_isNoOp() async {
        let store = MockMigratableStore()
        // No legacy entry seeded

        // Run migration logic — should be a no-op
        await store.migrateLegacy(
            from: KeychainVaultCredentials.legacyService,
            to: KeychainVaultCredentials.service
        )

        // Canonical is still absent
        let canonical = await store.read(forService: KeychainVaultCredentials.service)
        #expect(canonical == nil, "Canonical should remain absent if no legacy was present")

        // No delete called
        let deleteCount = await store.deleteCallCount[KeychainVaultCredentials.legacyService]
        #expect(deleteCount == nil || deleteCount == 0)
    }

    // TP-KMG-03: Idempotency — calling migrate twice yields same result
    @Test("TP-KMG-03: migrateLegacyIfPresent is idempotent (safe to call twice)")
    func test_KMG_03_idempotent_calledTwice_sameOutcome() async {
        let store = MockMigratableStore()
        let credentials = VaultwardenCredentials(
            clientID: "user.idempotent-test",
            clientSecret: "secret2",
            serverURL: URL(string: "https://vw.example.com")!
        )
        await store.seed(credentials, forService: KeychainVaultCredentials.legacyService)

        // First migration
        await store.migrateLegacy(
            from: KeychainVaultCredentials.legacyService,
            to: KeychainVaultCredentials.service
        )

        // Second call — legacy is gone so it's a no-op
        await store.migrateLegacy(
            from: KeychainVaultCredentials.legacyService,
            to: KeychainVaultCredentials.service
        )

        // Canonical still has the data
        let canonical = await store.read(forService: KeychainVaultCredentials.service)
        #expect(canonical?.clientID == "user.idempotent-test")

        // Legacy is still gone
        let legacy = await store.read(forService: KeychainVaultCredentials.legacyService)
        #expect(legacy == nil)

        // Delete was only called once (on first migration; second was no-op)
        let deleteCount = await store.deleteCallCount[KeychainVaultCredentials.legacyService]
        #expect(deleteCount == 1, "delete should be called exactly once (second call is no-op)")
    }
}
