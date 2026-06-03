import Foundation
import ShiSecretsKit

// InlineFooter — the `shi secret get` footer renderer (BR-A-06).
//
// The footer is written to stderr; plaintext/ephemeral-token bytes go
// to stdout. The footer uses ONLY the vocabulary locked in Phase 5a
// (features/shikki-secrets-broker.md — "dies in", "reborn",
// "dormant · no fetches in 30d · rotation suspended", etc.).
//
// BR-A-06 hygiene: the footer MUST NEVER render `expires_at` anywhere.
// A unit test greps this file (and the rendered output) to guarantee it.
//
// Four variants (mocked in Phase 5a):
//   A — Normal warm
//   B — Dormant
//   C — LLM-touched (MCP)
//   D — Anomaly-flagged
//
// The renderer takes a pre-computed `InlineFooterContext` struct so the
// test can pin the inputs (no Date() in the render path); production
// callers build the context from a VaultEntryRef + TokenRegistry.Row
// + last-caller metadata.

public enum InlineFooterVariant: String, Sendable, Equatable, CaseIterable {
    case normalWarm       // A
    case dormant          // B
    case llmTouchedMCP    // C
    case anomalyFlagged   // D
}

public struct InlineFooterContext: Sendable, Equatable {
    public let variant: InlineFooterVariant
    /// Age string like "4d", "47d", "6h". Pre-computed.
    public let age: String
    /// Tier word — `warm`, `hot`, `cool`, `external`.
    public let tier: String
    /// "rotates in 3d" / "no fetches in 30d · rotation suspended" / nil.
    public let rotationPhrase: String?
    /// Last caller tag — e.g. "woodpecker-ci@nuc-dev 12m ago".
    public let lastCaller: String
    /// The llm_touched bit — renders `llm_touched=true|false`.
    public let llmTouched: Bool
    /// Token death phrase — "token dies in 58m".
    public let tokenDies: String
    /// Optional anomaly tail (variant D only).
    public let anomalyTail: String?

    public init(
        variant: InlineFooterVariant,
        age: String,
        tier: String,
        rotationPhrase: String?,
        lastCaller: String,
        llmTouched: Bool,
        tokenDies: String,
        anomalyTail: String? = nil
    ) {
        self.variant = variant
        self.age = age
        self.tier = tier
        self.rotationPhrase = rotationPhrase
        self.lastCaller = lastCaller
        self.llmTouched = llmTouched
        self.tokenDies = tokenDies
        self.anomalyTail = anomalyTail
    }
}

public enum InlineFooter {

    /// Render the footer as a plain (un-ANSI) string. The real CLI wraps
    /// cells in ANSI escape sequences via `ansi(_:on:)`; snapshot tests
    /// compare against the plain form so they don't drift on terminal
    /// capability changes.
    public static func render(_ ctx: InlineFooterContext) -> String {
        switch ctx.variant {
        case .normalWarm:
            // # age 4d · warm, rotates in 3d · last: … · llm_touched=false · token dies in 58m
            return "# age \(ctx.age) · \(ctx.tier), \(ctx.rotationPhrase ?? "")"
                + " · last: \(ctx.lastCaller)"
                + " · llm_touched=\(ctx.llmTouched)"
                + " · \(ctx.tokenDies)"
        case .dormant:
            // # age 47d · dormant · no fetches in 30d · rotation suspended · last: … · llm_touched=false · token dies in 58m
            return "# age \(ctx.age) · dormant · no fetches in 30d · rotation suspended"
                + " · last: \(ctx.lastCaller)"
                + " · llm_touched=\(ctx.llmTouched)"
                + " · \(ctx.tokenDies)"
        case .llmTouchedMCP:
            // # age 6h · warm · last: claude@tusken (mcp) just now · llm_touched=true · parent rotates within 60m of SessionEnd · token dies in 47m
            return "# age \(ctx.age) · \(ctx.tier)"
                + " · last: \(ctx.lastCaller)"
                + " · llm_touched=true · parent rotates within 60m of SessionEnd"
                + " · \(ctx.tokenDies)"
        case .anomalyFlagged:
            // # age 4d · warm · last: … · llm_touched=false · token dies in 58m · ⚠ anomaly: hibp match · rotation queued · reborn within 60s
            return "# age \(ctx.age) · \(ctx.tier)"
                + " · last: \(ctx.lastCaller)"
                + " · llm_touched=\(ctx.llmTouched)"
                + " · \(ctx.tokenDies)"
                + " · \(ctx.anomalyTail ?? "⚠ anomaly · rotation queued · reborn within 60s")"
        }
    }

    /// Review finding U14 — the full @Kintsugi-locked hygiene scan.
    /// Matches the four variants agreed in Phase 5a:
    ///   * `expires_at`      (original substring)
    ///   * `expires`         (word-form)
    ///   * `expired`         (past-tense smuggle)
    ///   * `will expire`     (future-tense smuggle)
    /// The footer vocabulary is "dies in" / "reborn" / "rotates in" /
    /// "rotation suspended" only. A rendered string containing any of
    /// the forbidden tokens is a vocabulary leak.
    ///
    /// Case-insensitive match so a future ANSI renderer that uppercases
    /// a word cannot slip past the scan. The `revoked` word is NOT in
    /// the hygiene set — it remains a legitimate TUI term in token
    /// contexts (e.g. `shi token revoke-all-bots`). This function
    /// scopes only the secret-footer output surface.
    public static let forbiddenHygieneTokens: [String] = [
        "expires_at", "expires", "expired", "will expire"
    ]

    /// BR-A-06 hygiene guard — the rendered footer MUST NEVER contain
    /// any of the `forbiddenHygieneTokens`. Useful for call-site
    /// self-checks; the unit test asserts this against every variant.
    public static func isHygienic(_ rendered: String) -> Bool {
        let lower = rendered.lowercased()
        for token in forbiddenHygieneTokens {
            if lower.contains(token.lowercased()) { return false }
        }
        return true
    }
}
