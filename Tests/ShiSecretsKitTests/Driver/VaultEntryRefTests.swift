import Foundation
import Testing
@testable import ShiSecretsKit

// VaultEntryRef + HumanRunbook tests (Task 11 — BR-B-01).
// Shape-only — full vault I/O lives in Waves 3+ (BWClient driver bridge).

@Suite("VaultEntryRef")
struct VaultEntryRefTests {

    @Test("VaultEntryRef requires rotationDue, lastRotated, scope, usageState")
    func vaultEntryRequiresCustomFields() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let entry = VaultEntryRef(
            name: "ovh:dns",
            scope: "ovh.dns.read:example.com",
            tier: .hot,
            usageState: .hot,
            lastRotated: now,
            rotationDue: now.addingTimeInterval(24 * 3600)
        )

        // Round-trip keeps every required field readable.
        #expect(entry.name == "ovh:dns")
        #expect(entry.scope == "ovh.dns.read:example.com")
        #expect(entry.tier == .hot)
        #expect(entry.usageState == .hot)
        #expect(entry.lastRotated == now)
        #expect(entry.rotationDue == now.addingTimeInterval(24 * 3600))

        // Codable roundtrip survives.
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let data = try encoder.encode(entry)
        let decoded = try decoder.decode(VaultEntryRef.self, from: data)
        #expect(decoded == entry)
    }

    @Test(
        "VaultEntryRef.usageState accepts every UsageState",
        arguments: UsageState.allCases
    )
    func usageStateValidValues(state: UsageState) throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let entry = VaultEntryRef(
            name: "brevo:api",
            scope: "brevo.api.read",
            tier: .warm,
            usageState: state,
            lastRotated: now,
            rotationDue: now.addingTimeInterval(168 * 3600)
        )
        #expect(entry.usageState == state)
    }

    @Test("HumanRunbook carries a path + ordered steps")
    func humanRunbookShape() {
        let runbook = HumanRunbook(
            path: "runbooks/shikki-secrets-rotate-ovh.md",
            steps: [
                "Open OVH console",
                "Regenerate the application key",
                "Update bw entry `ovh:dns` with the new secret",
            ]
        )
        #expect(runbook.path.hasSuffix(".md"))
        #expect(runbook.steps.count == 3)
    }
}
