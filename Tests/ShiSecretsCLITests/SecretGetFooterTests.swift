import Foundation
@testable import ShiSecretsCLI
import Testing

@Suite("SecretGetFooter")
struct SecretGetFooterTests {

    // T57 — variant A (Normal warm).
    @Test("inline footer variant A — normal warm — dies_in + tier + rotates_in + last_caller + llm_touched")
    func test_cli_secretGet_inlineFooterFormat_variantA_normalWarm_snapshot() {
        let ctx = InlineFooterContext(
            variant: .normalWarm,
            age: "4d",
            tier: "warm",
            rotationPhrase: "rotates in 3d",
            lastCaller: "woodpecker-ci@nuc-dev 12m ago",
            llmTouched: false,
            tokenDies: "token dies in 58m"
        )
        let rendered = InlineFooter.render(ctx)
        let expected = "# age 4d · warm, rotates in 3d · last: woodpecker-ci@nuc-dev 12m ago · llm_touched=false · token dies in 58m"
        #expect(rendered == expected)
    }

    @Test("inline footer variant B — dormant — no fetches in 30d · rotation suspended (Kintsugi lock)")
    func test_cli_secretGet_inlineFooterFormat_variantB_dormant_snapshot() {
        let ctx = InlineFooterContext(
            variant: .dormant,
            age: "47d",
            tier: "warm",          // tier field is present but un-rendered in B
            rotationPhrase: nil,
            lastCaller: "ci-legacy@nuc-dev 31d ago",
            llmTouched: false,
            tokenDies: "token dies in 58m"
        )
        let rendered = InlineFooter.render(ctx)
        let expected = "# age 47d · dormant · no fetches in 30d · rotation suspended · last: ci-legacy@nuc-dev 31d ago · llm_touched=false · token dies in 58m"
        #expect(rendered == expected)
    }

    @Test("inline footer variant C — llm_touched (MCP) — parent rotates within 60m of SessionEnd")
    func test_cli_secretGet_inlineFooterFormat_variantC_llmTouchedMCP_snapshot() {
        let ctx = InlineFooterContext(
            variant: .llmTouchedMCP,
            age: "6h",
            tier: "warm",
            rotationPhrase: nil,
            lastCaller: "claude@tusken (mcp) just now",
            llmTouched: true,
            tokenDies: "token dies in 47m"
        )
        let rendered = InlineFooter.render(ctx)
        let expected = "# age 6h · warm · last: claude@tusken (mcp) just now · llm_touched=true · parent rotates within 60m of SessionEnd · token dies in 47m"
        #expect(rendered == expected)
    }

    @Test("inline footer variant D — anomaly-flagged — hibp match · rotation queued · reborn within 60s")
    func test_cli_secretGet_inlineFooterFormat_variantD_anomalyFlagged_snapshot() {
        let ctx = InlineFooterContext(
            variant: .anomalyFlagged,
            age: "4d",
            tier: "warm",
            rotationPhrase: nil,
            lastCaller: "woodpecker-ci@nuc-dev 12m ago",
            llmTouched: false,
            tokenDies: "token dies in 58m",
            anomalyTail: "⚠ anomaly: hibp match · rotation queued · reborn within 60s"
        )
        let rendered = InlineFooter.render(ctx)
        let expected = "# age 4d · warm · last: woodpecker-ci@nuc-dev 12m ago · llm_touched=false · token dies in 58m · ⚠ anomaly: hibp match · rotation queued · reborn within 60s"
        #expect(rendered == expected)
    }

    // T57 — BR-A-06 hygiene guard across ALL variants.
    @Test("footer uses `dies in` — NEVER the string `expires_at` across every variant (BR-A-06)")
    func test_cli_secretGet_footerUsesDiesAt_neverExpiresAtString() {
        for variant in InlineFooterVariant.allCases {
            let ctx = InlineFooterContext(
                variant: variant,
                age: "1d",
                tier: "warm",
                rotationPhrase: variant == .normalWarm ? "rotates in 1d" : nil,
                lastCaller: "some-caller 1m ago",
                llmTouched: variant == .llmTouchedMCP,
                tokenDies: "token dies in 10m",
                anomalyTail: variant == .anomalyFlagged ? "⚠ anomaly: hibp match · rotation queued · reborn within 60s" : nil
            )
            let rendered = InlineFooter.render(ctx)
            #expect(InlineFooter.isHygienic(rendered))
            #expect(rendered.contains("dies in"))
            #expect(!rendered.contains("expires_at"))
        }
    }

    @Test("isHygienic rejects full vocabulary set (U14)")
    func test_inlineFooter_isHygienic_rejectsFullVocabulary_U14() {
        // Review finding U14 — the hygiene scan rejects the full
        // @Kintsugi-locked forbidden vocabulary, not just `expires_at`.
        #expect(!InlineFooter.isHygienic("token expires_at 2026-01-01"))
        #expect(!InlineFooter.isHygienic("token expires in 10m"))
        #expect(!InlineFooter.isHygienic("token expired 1h ago"))
        #expect(!InlineFooter.isHygienic("token will expire shortly"))
        // Case-insensitive.
        #expect(!InlineFooter.isHygienic("TOKEN EXPIRES IN 10M"))
        // Legitimate vocabulary passes.
        #expect(InlineFooter.isHygienic("token dies in 10m"))
        #expect(InlineFooter.isHygienic("reborn within 60s"))
    }
}
