import Foundation
import Testing
@testable import ShiSecretsKit

// RotationEngine dormancy tests (Task 29 — BR-B-05, BR-B-06, BR-C-04, BR-C-05).
//
// Dormancy triggers on all-zero windows; dormant + archived are filtered
// out of `tick`; a fetch on a dormant entry exits dormancy, resets the
// counter, and re-schedules the next rotation.

@Suite("Dormancy")
struct DormancyTests {

    @Test("all windows zero → dormant")
    func test_rotation_allWindowsZero_triggersDormant() async {
        let engine = RotationEngine(
            audit: AuditWriter(),
            seams: SeamsWriter(),
            registry: TokenRegistry()
        )
        let state = engine.evaluateDormancy(f24h: 0, f7d: 0, f30d: 0)
        #expect(state == .dormant)
        // Any non-zero window keeps prior state.
        #expect(engine.evaluateDormancy(f24h: 1, f7d: 0, f30d: 0) == nil)
        #expect(engine.evaluateDormancy(f24h: 0, f7d: 1, f30d: 0) == nil)
        #expect(engine.evaluateDormancy(f24h: 0, f7d: 0, f30d: 1) == nil)
    }

    @Test("scheduled run skips dormant entries")
    func test_rotation_scheduledRun_skipsDormantEntries() async {
        let fixedNow = Date(timeIntervalSince1970: 1_700_000_000)
        let engine = RotationEngine(
            clock: RotationClock(now: { fixedNow }),
            audit: AuditWriter(),
            seams: SeamsWriter(),
            registry: TokenRegistry()
        )
        // Two entries; both overdue; one is dormant, one is active.
        let active = VaultEntryRef(
            name: "ACTIVE", scope: "ovh/*", tier: .hot,
            usageState: .hot,
            lastRotated: fixedNow.addingTimeInterval(-3600 * 48),
            rotationDue: fixedNow.addingTimeInterval(-3600)
        )
        let dormant = VaultEntryRef(
            name: "DORMANT", scope: "ovh/*", tier: .hot,
            usageState: .dormant,
            lastRotated: fixedNow.addingTimeInterval(-3600 * 48),
            rotationDue: fixedNow.addingTimeInterval(-3600)
        )
        await engine.seed(entry: active)
        await engine.seed(entry: dormant)

        let due = await engine.tick(track: .hot)
        #expect(due == ["ACTIVE"])
    }

    @Test("30d zero fetches flags dormant, suspends rotation")
    func test_vaultEntry_30dZeroFetches_flagsDormant_suspendsRotation() async throws {
        let engine = RotationEngine(
            audit: AuditWriter(),
            seams: SeamsWriter(),
            registry: TokenRegistry()
        )
        let entry = await engine.createEntry(name: "OLD_KEY", scope: "ovh/*", tier: .warm)
        // All windows zero.
        await engine.setFetchCounters(secret: "OLD_KEY", f24h: 0, f7d: 0, f30d: 0)
        let rotated = try await engine.applyRotation(entry: entry)
        // Rotation ran (for the just-seeded key), but next due is
        // distantFuture because engine detected dormancy.
        #expect(rotated.rotationDue == .distantFuture)
    }

    @Test("dormant receives fetch → exits dormant, resets window, reschedules")
    func test_vaultEntry_dormantReceivesFetch_exitsDormant_resetsWindow_schedulesNextTick() async {
        let fixedNow = Date(timeIntervalSince1970: 1_700_000_000)
        let engine = RotationEngine(
            clock: RotationClock(now: { fixedNow }),
            audit: AuditWriter(),
            seams: SeamsWriter(),
            registry: TokenRegistry()
        )
        let dormant = VaultEntryRef(
            name: "SLEEPY", scope: "ovh/*", tier: .warm,
            usageState: .dormant,
            lastRotated: fixedNow.addingTimeInterval(-3600 * 24 * 60),
            rotationDue: .distantFuture
        )
        await engine.seed(entry: dormant)
        await engine.setFetchCounters(secret: "SLEEPY", f24h: 0, f7d: 0, f30d: 0)

        let exited = await engine.onFetch(secret: "SLEEPY")
        #expect(exited == true)

        let after = await engine.entry(name: "SLEEPY")
        #expect(after?.usageState == .warm)
        let counters = await engine.fetchCounters(secret: "SLEEPY")
        #expect(counters.f24h == 1 && counters.f7d == 0 && counters.f30d == 0)
        // baseHours for .warm is 168h.
        let expectedNext = fixedNow.addingTimeInterval(168 * 3600)
        #expect(abs((after?.rotationDue ?? .distantPast).timeIntervalSince(expectedNext)) < 1)
    }
}
