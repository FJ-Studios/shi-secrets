import Foundation

// UsageState — the observable state of a vault entry in the rotation engine.
//
// hot / warm / cool / external map to `Tier` and drive base-cadence hours.
// `dormant` is set when an entry has zero fetches across all three windows
// (BR-C-04) and suspends scheduled rotation (BR-C-05). `archived` is set
// when an entry is retired (BR-B-08); the broker refuses token issuance
// for archived entries (BR-B-09).

public enum UsageState: String, Codable, Sendable, CaseIterable, Equatable {
    case hot
    case warm
    case cool
    case dormant
    case external
    case archived
}
