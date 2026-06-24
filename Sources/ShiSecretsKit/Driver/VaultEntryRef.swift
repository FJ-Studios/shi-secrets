import Foundation

// VaultEntryRef — broker-side snapshot of a Vaultwarden entry.
//
// BR-B-01 mandates that every vault entry carry rotation_due, last_rotated,
// scope, and usage_state. We also carry the derived `tier` so the rotation
// engine can look up `baseHours` / `weights` without a second round-trip.
// The ref is deliberately a value type: no ciphertext, no plaintext, no
// vendor session tokens — only the metadata required to schedule rotation
// and render the `shi secret get` inline footer.
//
// WIRE FORMAT (single SoT — operator mandate 2026-06-24):
// Date fields (last_rotated, rotation_due) are ISO 8601 RFC 3339 UTC strings
// ONLY — e.g. "2026-06-24T08:30:00Z". Double/Unix-epoch inputs are invalid
// and will throw DecodingError. No backward compat, no distantPast fallback.
// Callers MUST set JSONDecoder.dateDecodingStrategy = .iso8601.
// See Sources/ShiSecretsKit/WIRE_FORMAT.md for the canonical spec.

public struct VaultEntryRef: Codable, Sendable, Equatable {
    public let name: String
    public let scope: String
    public let tier: Tier
    public let usageState: UsageState
    public let lastRotated: Date
    public let rotationDue: Date

    enum CodingKeys: String, CodingKey {
        case name
        case scope
        case tier
        case usageState = "usage_state"
        case lastRotated = "last_rotated"
        case rotationDue = "rotation_due"
    }

    public init(
        name: String,
        scope: String,
        tier: Tier,
        usageState: UsageState,
        lastRotated: Date,
        rotationDue: Date
    ) {
        self.name = name
        self.scope = scope
        self.tier = tier
        self.usageState = usageState
        self.lastRotated = lastRotated
        self.rotationDue = rotationDue
    }
}
