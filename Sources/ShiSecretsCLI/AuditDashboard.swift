import Foundation
import ShiSecretsKit

// AuditDashboard — `shi audit secrets --tui` renderer (T62 — BR-G-03).
//
// Three visual states, matching Phase 5a mockups byte-for-byte in their
// un-ANSI form:
//   healthy    — all three counters are 0
//   llmInFlight — llm_touched > 0, stale = 0
//   incident   — stale > 0 AND denied24h > 0
//
// Render output is a multi-line string; snapshot tests compare against
// inline literals so CLI UI drift is caught in code review.
//
// The renderer is Katagami-free on purpose: Katagami's target (CoreKit +
// ShikkiTestRunner platform constraints) would pull heavy deps into a
// CLI that just needs to print ASCII art. This renderer uses only
// Foundation + `String`-concatenation + box-drawing chars from CP-437;
// swap-in to Katagami is a future refactor that keeps the same public
// `render(_:)` signature.

public enum DashboardState: String, Sendable, Equatable, CaseIterable {
    case healthy
    case llmInFlight
    case incident
}

public struct DashboardRow: Sendable, Equatable {
    public enum Color: String, Sendable, Equatable {
        case blue       // warm
        case grey       // cool
        case dim        // external
        case magenta    // llm-touched
        case red        // deny / seam
        case green      // success / allow
    }

    /// Review finding #12 — typed row kind with canonical `glyph` +
    /// `color` pairings so callers cannot drift by passing mismatched
    /// strings (e.g. a `warm` marker under `.red`). Legacy string-based
    /// initializer is retained as a compatibility shim but marked
    /// deprecated so new call sites pick the enum form.
    public enum RowKind: String, Sendable, Equatable, CaseIterable {
        case warm
        case cool
        case ext
        case llm
        case deny
        case seam

        /// 4-char marker glyph pinned to locked CLI vocabulary (Phase 5a
        /// mockup). Padding keeps timeline columns aligned.
        public var glyph: String {
            switch self {
            case .warm: return "warm"
            case .cool: return "cool"
            case .ext:  return "ext "
            case .llm:  return "llm "
            case .deny: return "deny"
            case .seam: return "seam"
            }
        }

        public var color: Color {
            switch self {
            case .warm: return .blue
            case .cool: return .grey
            case .ext:  return .dim
            case .llm:  return .magenta
            case .deny: return .red
            case .seam: return .red
            }
        }
    }

    public let time: String       // "13:41"
    public let kind: RowKind
    public let secret: String
    public let op: String

    /// Convenience accessor mapping to the row's typed glyph string.
    public var marker: String { kind.glyph }
    /// Convenience accessor mapping to the row's typed color.
    public var color: Color { kind.color }

    public init(time: String, kind: RowKind, secret: String, op: String) {
        self.time = time
        self.kind = kind
        self.secret = secret
        self.op = op
    }

    /// Deprecated string-based initializer. Review finding #12 — kept for
    /// source-compat with legacy callers; resolves the 4-char marker
    /// string back to a `RowKind` via exact match (falls back to `.warm`
    /// on unknown marker to preserve prior healthy-state behavior).
    @available(*, deprecated, message: "Use DashboardRow(time:kind:secret:op:) — RowKind drives glyph + color centrally.")
    public init(time: String, marker: String, secret: String, op: String, color: Color) {
        self.time = time
        self.secret = secret
        self.op = op
        // Resolve kind from marker string; color parameter is ignored
        // (RowKind owns the color pairing now).
        _ = color
        let trimmed = marker.trimmingCharacters(in: .whitespaces)
        self.kind = RowKind(rawValue: trimmed) ?? .warm
    }
}

public struct AuditDashboardContext: Sendable, Equatable {
    public let hostName: String           // "nuc-dev"
    public let brokerVersion: String      // "v1.0"
    public let nowClock: String           // "13:42"
    public let staleCount: Int
    public let llmTouchedUnrotated: Int
    public let denied24h: Int
    public let rows: [DashboardRow]
    public let footerLine: String         // "● all healthy · 0 anomalies" / "⚠ …"
    public let state: DashboardState
    public init(
        hostName: String,
        brokerVersion: String,
        nowClock: String,
        staleCount: Int,
        llmTouchedUnrotated: Int,
        denied24h: Int,
        rows: [DashboardRow],
        footerLine: String,
        state: DashboardState
    ) {
        self.hostName = hostName
        self.brokerVersion = brokerVersion
        self.nowClock = nowClock
        self.staleCount = staleCount
        self.llmTouchedUnrotated = llmTouchedUnrotated
        self.denied24h = denied24h
        self.rows = rows
        self.footerLine = footerLine
        self.state = state
    }
}

public enum AuditDashboard {

    /// The keybind strip at the bottom of the TUI. Matches Phase 5a locked
    /// copy exactly: `r rotate · R revoke · / filter · q quit`.
    public static let keybindLine = "r rotate · R revoke · / filter · q quit"

    public static func render(_ ctx: AuditDashboardContext) -> String {
        var lines: [String] = []
        lines.append("┌─ shi audit secrets ─── \(ctx.hostName) · broker \(ctx.brokerVersion) ── \(ctx.nowClock) ─┐")
        lines.append("  stale \(ctx.staleCount)   llm-touched unrotated \(ctx.llmTouchedUnrotated)   denied 24h \(ctx.denied24h)")
        lines.append("├── recent fetches ───────────────┤")
        for row in ctx.rows {
            lines.append("│ \(row.time) \(row.marker)  \(pad(row.secret, 14)) \(row.op)")
        }
        lines.append("│ \(ctx.footerLine)")
        lines.append("├─────────────────────────────────┤")
        lines.append("│ \(keybindLine)")
        lines.append("└─────────────────────────────────┘")
        return lines.joined(separator: "\n")
    }

    private static func pad(_ s: String, _ width: Int) -> String {
        if s.count >= width { return String(s.prefix(width)) }
        return s + String(repeating: " ", count: width - s.count)
    }

    /// Derive a DashboardContext from live broker signals. Pure — tests
    /// pin inputs and assert the resulting DashboardState enum case.
    public static func deriveState(
        stale: Int,
        llmTouchedUnrotated: Int,
        denied24h: Int
    ) -> DashboardState {
        if stale > 0 && denied24h > 0 { return .incident }
        if llmTouchedUnrotated > 0 && stale == 0 { return .llmInFlight }
        return .healthy
    }
}
