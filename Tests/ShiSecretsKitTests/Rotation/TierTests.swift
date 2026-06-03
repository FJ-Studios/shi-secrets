import Foundation
import Testing
@testable import ShiSecretsKit

// Tier / UsageState tests (Task 7 — BR-C-01, BR-C-03, BR-B-01).
// The tier-adaptive weight table was locked 2026-04-20:
// hot bursts weighted, cool averaged, external horizon-weighted.

@Suite("Tier")
struct TierTests {

    @Test(
        "base tier hours map: hot=24 warm=168 cool=720 external=2160",
        arguments: [
            (Tier.hot, 24),
            (Tier.warm, 168),
            (Tier.cool, 720),
            (Tier.external, 2160),
        ]
    )
    func baseTierHoursMap(pair: (Tier, Int)) {
        #expect(pair.0.baseHours == pair.1)
    }

    @Test("tier weights: hot weights 24h bursts, cool weights 30d average")
    func tierWeightsHotBurstCoolAverage() {
        // Hot: bursts matter — 24h weight beats 30d by 20x.
        #expect(Tier.hot.weights.w24h == 1.0)
        #expect(Tier.hot.weights.w7d == 0.2)
        #expect(Tier.hot.weights.w30d == 0.05)
        #expect(Tier.hot.weights.w24h > Tier.hot.weights.w30d * 10)

        // Cool: long average carries weight — 30d is within 2x of 24h.
        #expect(Tier.cool.weights.w24h == 0.5)
        #expect(Tier.cool.weights.w7d == 0.5)
        #expect(Tier.cool.weights.w30d == 0.3)
        #expect(Tier.cool.weights.w30d >= Tier.cool.weights.w24h / 2)
    }

    @Test("fetch rate formula is horizon-weighted for external tier")
    func fetchRateFormulaExternalHorizonWeighted() {
        // external: w30d is the largest — vendor-gated rotation leans on the
        // long horizon, not bursts.
        let w = Tier.external.weights
        #expect(w.w30d > w.w7d)
        #expect(w.w7d > w.w24h)
        #expect(w.w30d == 0.5)
        #expect(w.w7d == 0.4)
        #expect(w.w24h == 0.3)
    }
}
