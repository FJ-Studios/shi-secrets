import Foundation
import Testing
@testable import ShiSecretsKit

// VaultEntryRef + HumanRunbook tests (Task 11 — BR-B-01).
// Shape-only — full vault I/O lives in Waves 3+ (BWClient driver bridge).
//
// W0 update: flexible date decoding REMOVED per operator mandate 2026-06-24.
// ISO 8601 RFC 3339 UTC is the ONLY valid wire format for date fields.
// Double/null/missing inputs now throw — see BrokerWireDateFormatTests.swift
// for the full 6-test regression suite (T-W0-01 through T-W0-06).

@Suite("VaultEntryRef")
struct VaultEntryRefTests {

    // MARK: - W0: ISO 8601-only date decoding (single SoT per operator mandate)

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

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let entry = try decoder.decode(VaultEntryRef.self, from: json)

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
