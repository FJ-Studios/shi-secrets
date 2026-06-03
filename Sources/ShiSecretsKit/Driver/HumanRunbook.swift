import Foundation

// HumanRunbook — the per-vendor manual-fallback document path + step list.
//
// Drivers that cannot currently automate rotation (or that have a
// high-risk rotation path we'd rather not automate in v1) expose a
// `HumanRunbook` so the TUI can open the markdown file and walk the
// operator through the exact sequence. v1 OVH/Brevo/GitHub drivers set
// `humanFallback = nil`; the slot exists so later vendors can mix
// automated and manual flows under a single protocol.

public struct HumanRunbook: Codable, Sendable, Equatable {
    public let path: String
    public let steps: [String]

    public init(path: String, steps: [String]) {
        self.path = path
        self.steps = steps
    }
}
