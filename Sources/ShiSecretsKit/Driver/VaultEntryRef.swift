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
// Date-field decoding is tolerant: the broker emits ISO 8601 strings
// (e.g. "2026-06-23T18:00:00Z") but earlier broker versions may emit Unix
// epoch doubles. The custom init(from:) handles both, falling back to
// Date.distantPast on any parse failure so a single malformed entry never
// crashes the full `shi secrets list` response.

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

    // MARK: - Decodable (schema-drift tolerant)

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.name = try container.decode(String.self, forKey: .name)
        self.scope = try container.decode(String.self, forKey: .scope)
        self.tier = try container.decode(Tier.self, forKey: .tier)
        self.usageState = try container.decode(UsageState.self, forKey: .usageState)
        self.lastRotated = try Self.decodeFlexibleDate(from: container, forKey: .lastRotated)
        self.rotationDue = try Self.decodeFlexibleDate(from: container, forKey: .rotationDue)
    }

    // decodeFlexibleDate attempts ISO 8601 string first, then Unix Double,
    // then gracefully falls back to Date.distantPast for null/missing fields.
    // This prevents a single malformed last_rotated from crashing the entire
    // `shi secrets list` response (W2 fix — broker schema drift).
    //
    // Formatters are created per-call to avoid shared mutable state under
    // Swift 6 strict concurrency (ISO8601DateFormatter is not Sendable).
    private static func decodeFlexibleDate(
        from container: KeyedDecodingContainer<CodingKeys>,
        forKey key: CodingKeys
    ) throws -> Date {
        // (1) Null / missing — graceful default
        if (try? container.decodeNil(forKey: key)) == true {
            return .distantPast
        }
        if !container.contains(key) {
            return .distantPast
        }
        // (2) ISO 8601 string (canonical broker format)
        if let str = try? container.decode(String.self, forKey: key) {
            // Try with fractional seconds first, then without
            let withFractional: ISO8601DateFormatter = {
                let f = ISO8601DateFormatter()
                f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
                return f
            }()
            let basic: ISO8601DateFormatter = {
                let f = ISO8601DateFormatter()
                f.formatOptions = [.withInternetDateTime]
                return f
            }()
            if let date = withFractional.date(from: str) ?? basic.date(from: str) {
                return date
            }
            // String present but unparseable — graceful default
            return .distantPast
        }
        // (3) Unix epoch Double (legacy broker format)
        if let unix = try? container.decode(Double.self, forKey: key) {
            return Date(timeIntervalSince1970: unix)
        }
        // (4) Absolute fallback — never crash the list response
        return .distantPast
    }
}
