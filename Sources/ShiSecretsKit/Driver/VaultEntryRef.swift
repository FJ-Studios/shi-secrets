import Foundation

// VaultEntryRef — broker-side snapshot of a Vaultwarden entry.
//
// BR-B-01 mandates that every vault entry carry rotation_due, last_rotated,
// scope, and usage_state. We also carry the derived `tier` so the rotation
// engine can look up `baseHours` / `weights` without a second round-trip.
// The ref is deliberately a value type: no ciphertext, no plaintext, no
// vendor session tokens — only the metadata required to schedule rotation
// and render the `shi secret get` inline footer.

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
