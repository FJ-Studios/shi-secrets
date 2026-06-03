import Foundation

// Tier — the rotation cadence class for a vault entry.
//
// `baseHours` is the nominal rotation cadence when fetch_rate is 0 (BR-C-03).
// `weights` are the tier-adaptive multipliers on the fetch-rate formula
// (BR-C-01 — locked 2026-04-20):
//
//   | Tier     | w24h | w7d | w30d | Rationale                                 |
//   |----------|-----:|----:|-----:|-------------------------------------------|
//   | hot      | 1.0  | 0.2 | 0.05 | bursts matter; long average is noise      |
//   | warm     | 1.0  | 0.3 | 0.10 | balanced baseline                         |
//   | cool     | 0.5  | 0.5 | 0.30 | long average carries weight               |
//   | external | 0.3  | 0.4 | 0.50 | horizon-weighted; vendor-gated rotation   |

public enum Tier: String, Codable, Sendable, CaseIterable, Equatable {
    case hot
    case warm
    case cool
    case external

    public var baseHours: Int {
        switch self {
        case .hot:      return 24
        case .warm:     return 168
        case .cool:     return 720
        case .external: return 2160
        }
    }

    public struct Weights: Sendable, Codable, Equatable {
        public let w24h: Double
        public let w7d: Double
        public let w30d: Double

        public init(w24h: Double, w7d: Double, w30d: Double) {
            self.w24h = w24h
            self.w7d = w7d
            self.w30d = w30d
        }
    }

    public var weights: Weights {
        switch self {
        case .hot:      return Weights(w24h: 1.0, w7d: 0.2, w30d: 0.05)
        case .warm:     return Weights(w24h: 1.0, w7d: 0.3, w30d: 0.10)
        case .cool:     return Weights(w24h: 0.5, w7d: 0.5, w30d: 0.30)
        case .external: return Weights(w24h: 0.3, w7d: 0.4, w30d: 0.50)
        }
    }

    /// The `UsageState` a fresh (or dormancy-exit) vault entry of this
    /// tier should carry. Review finding #14 — hoisted as a computed
    /// property so `RotationEngine.createEntry` and `onFetch` no longer
    /// duplicate the 4-case Tier → UsageState switch.
    public var defaultUsageState: UsageState {
        switch self {
        case .hot:      return .hot
        case .warm:     return .warm
        case .cool:     return .cool
        case .external: return .external
        }
    }
}
