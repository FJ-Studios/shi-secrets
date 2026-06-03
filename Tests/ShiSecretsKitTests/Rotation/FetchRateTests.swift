import Foundation
import Testing
@testable import ShiSecretsKit

// RotationEngine.fetchRate (Task 27 — BR-C-01).
//
// Tier-adaptive weights (locked 2026-04-20):
//   hot:      w24h 1.0, w7d 0.2, w30d 0.05 → bursts weighted
//   warm:     w24h 1.0, w7d 0.3, w30d 0.10 → balanced
//   cool:     w24h 0.5, w7d 0.5, w30d 0.30 → average weighted
//   external: w24h 0.3, w7d 0.4, w30d 0.50 → horizon weighted

@Suite("FetchRate")
struct FetchRateTests {

    private func engine() async -> RotationEngine {
        RotationEngine(
            audit: AuditWriter(),
            seams: SeamsWriter(),
            registry: TokenRegistry()
        )
    }

    @Test(
        "fetch rate formula applies tier-adaptive weights",
        arguments: Tier.allCases
    )
    func test_rotation_fetchRateFormula_appliesTierAdaptiveWeights(tier: Tier) async {
        let engine = await engine()
        // Inputs: 10 / 50 / 200 chosen so each tier's weighted product is
        // distinctive enough that a flipped weight table would fail.
        let fr = engine.fetchRate(tier: tier, f24h: 10, f7d: 50, f30d: 200)
        let w = tier.weights
        let expected = 10.0 * w.w24h + 50.0 * w.w7d + 200.0 * w.w30d
        #expect(abs(fr - expected) < 0.0001)
    }

    @Test("hot bursts weighted, cool average weighted")
    func test_rotation_tierWeights_hotBurstWeighted_coolAverageWeighted() async {
        let engine = await engine()
        // Same counters across tiers — hot should exceed cool because
        // 24h weight is 2x larger; 30d weight is 6x smaller.
        let hot = engine.fetchRate(tier: .hot, f24h: 100, f7d: 0, f30d: 0)
        let cool = engine.fetchRate(tier: .cool, f24h: 100, f7d: 0, f30d: 0)
        #expect(hot > cool)

        // Conversely, on a 30d-only trace, cool exceeds hot (0.3 vs 0.05).
        let hot30 = engine.fetchRate(tier: .hot, f24h: 0, f7d: 0, f30d: 100)
        let cool30 = engine.fetchRate(tier: .cool, f24h: 0, f7d: 0, f30d: 100)
        #expect(cool30 > hot30)
    }

    @Test("external tier is horizon-weighted")
    func test_rotation_fetchRateFormula_externalHorizonWeighted() async {
        let engine = await engine()
        // w30d > w7d > w24h for external — a 30d-only trace beats any
        // other horizon at equal counter value.
        let ext24 = engine.fetchRate(tier: .external, f24h: 100, f7d: 0, f30d: 0)
        let ext7 = engine.fetchRate(tier: .external, f24h: 0, f7d: 100, f30d: 0)
        let ext30 = engine.fetchRate(tier: .external, f24h: 0, f7d: 0, f30d: 100)
        #expect(ext30 > ext7)
        #expect(ext7 > ext24)
    }
}
