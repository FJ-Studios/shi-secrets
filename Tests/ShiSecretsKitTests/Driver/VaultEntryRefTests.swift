import Foundation
import Testing
@testable import ShiSecretsKit

// VaultEntryRef + HumanRunbook tests (Task 11 — BR-B-01).
// Shape-only — full vault I/O lives in Waves 3+ (BWClient driver bridge).
//
// W2 additions: flexible date decoding tests (fix/secrets-list-last-rotated-iso8601-decode)
// T1 — ISO 8601 string parses correctly
// T2 — Unix epoch Double parses correctly
// T3 — null/missing last_rotated is graceful (no error, distantPast default)

@Suite("VaultEntryRef")
struct VaultEntryRefTests {

    // MARK: - W2: Flexible date decoding (fix for ISO 8601 schema drift)

    @Test("T1: last_rotated as ISO 8601 string decodes correctly")
    func lastRotatedISO8601String() throws {
        let json = """
        {
            "name": "ovh:dns",
            "scope": "ovh.dns.read:example.com",
            "tier": "hot",
            "usage_state": "hot",
            "last_rotated": "2026-06-23T18:00:00Z",
            "rotation_due": "2026-06-24T18:00:00Z"
        }
        """.data(using: .utf8)!

        let entry = try JSONDecoder().decode(VaultEntryRef.self, from: json)

        // Verify the parsed date matches the ISO 8601 value exactly
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(identifier: "UTC")!
        let components = cal.dateComponents([.year, .month, .day, .hour, .minute, .second], from: entry.lastRotated)
        #expect(components.year == 2026)
        #expect(components.month == 6)
        #expect(components.day == 23)
        #expect(components.hour == 18)
        #expect(components.minute == 0)
        #expect(components.second == 0)
    }

    @Test("T2: last_rotated as Unix epoch Double decodes correctly")
    func lastRotatedUnixDouble() throws {
        // 1_735_000_000 = 2024-12-24T01:26:40Z
        let json = """
        {
            "name": "brevo:api",
            "scope": "brevo.api.send",
            "tier": "warm",
            "usage_state": "warm",
            "last_rotated": 1735000000,
            "rotation_due": 1735604800
        }
        """.data(using: .utf8)!

        let entry = try JSONDecoder().decode(VaultEntryRef.self, from: json)

        let expectedDate = Date(timeIntervalSince1970: 1_735_000_000)
        #expect(entry.lastRotated == expectedDate)
    }

    @Test("T3: null last_rotated is graceful — no error, distantPast default")
    func lastRotatedNullGraceful() throws {
        let json = """
        {
            "name": "gh:token",
            "scope": "github.repo.read",
            "tier": "cool",
            "usage_state": "cool",
            "last_rotated": null,
            "rotation_due": null
        }
        """.data(using: .utf8)!

        // Must not throw — null fields should default to distantPast
        let entry = try JSONDecoder().decode(VaultEntryRef.self, from: json)
        #expect(entry.lastRotated == Date.distantPast)
        #expect(entry.rotationDue == Date.distantPast)
    }

    @Test("T4: missing last_rotated key is graceful — no error, distantPast default")
    func lastRotatedMissingGraceful() throws {
        let json = """
        {
            "name": "gh:token",
            "scope": "github.repo.read",
            "tier": "cool",
            "usage_state": "cool"
        }
        """.data(using: .utf8)!

        // Must not throw — missing keys default to distantPast
        let entry = try JSONDecoder().decode(VaultEntryRef.self, from: json)
        #expect(entry.lastRotated == Date.distantPast)
        #expect(entry.rotationDue == Date.distantPast)
    }



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
