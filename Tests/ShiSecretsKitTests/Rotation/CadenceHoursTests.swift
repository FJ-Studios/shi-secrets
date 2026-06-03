import Foundation
import Testing
@testable import ShiSecretsKit

// RotationEngine.cadenceHours (Task 28 — BR-C-02, BR-C-09, BR-C-10).
//
// cadence = round(base / (1 + fr))  clamped to [1, base]
// dormant → .max (rotation suspended).

@Suite("CadenceHours")
struct CadenceHoursTests {

    private func engine() async -> RotationEngine {
        RotationEngine(
            audit: AuditWriter(),
            seams: SeamsWriter(),
            registry: TokenRegistry()
        )
    }

    @Test("rotation_due written from last_rotated plus cadence")
    func test_rotation_cadenceHoursFormula_writesRotationDueFromLastRotatedPlusCadence() async throws {
        let fixedNow = Date(timeIntervalSince1970: 1_700_000_000)
        let engine = RotationEngine(
            clock: RotationClock(now: { fixedNow }),
            audit: AuditWriter(),
            seams: SeamsWriter(),
            registry: TokenRegistry()
        )
        let created = await engine.createEntry(name: "OVH_APP_KEY", scope: "ovh/*", tier: .hot)
        // baseHours for .hot = 24h.
        let expectedDue = fixedNow.addingTimeInterval(24 * 3600)
        #expect(abs(created.rotationDue.timeIntervalSince(expectedDue)) < 1)
        #expect(created.lastRotated == fixedNow)
    }

    @Test("cadence clamped to a minimum of 1 hour")
    func test_rotation_cadenceHours_clampedMin1Hour() async {
        let engine = await engine()
        // hot baseHours=24; fr must drive raw below 1 to trigger the clamp.
        // raw = 24 / (1+fr) < 1  ⇔  fr > 23.
        let cadence = engine.cadenceHours(tier: .hot, fetchRate: 100.0, isDormant: false)
        #expect(cadence == 1)
    }

    @Test("cadence clamped to base when fr=0 and not dormant")
    func test_rotation_cadenceHours_clampedMaxBaseTierHoursWhenFetchRate24hZero_andNotDormant() async {
        let engine = await engine()
        for tier in Tier.allCases {
            let cadence = engine.cadenceHours(tier: tier, fetchRate: 0.0, isDormant: false)
            #expect(cadence == tier.baseHours)
        }
        // Dormant path returns .max (suspend).
        let suspended = engine.cadenceHours(tier: .hot, fetchRate: 0.0, isDormant: true)
        #expect(suspended == Int.max)
    }
}
