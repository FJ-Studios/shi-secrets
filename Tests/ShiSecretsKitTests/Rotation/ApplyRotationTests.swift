import Foundation
import Testing
@testable import ShiSecretsKit

// RotationEngine applyRotation + handleFailure + archive tests
// (Task 30 — BR-B-02, BR-B-03, BR-B-04, BR-B-08, BR-B-09).

@Suite("ApplyRotation")
struct ApplyRotationTests {

    @Test("on create → seeds last_rotated=now, rotation_due=+baseHours, usage_state from tier")
    func test_vaultEntry_onCreate_seedsLastRotatedNow_rotationDuePlusBaseTier_usageStateFromTier() async {
        let fixedNow = Date(timeIntervalSince1970: 1_700_000_000)
        let engine = RotationEngine(
            clock: RotationClock(now: { fixedNow }),
            audit: AuditWriter(),
            seams: SeamsWriter(),
            registry: TokenRegistry()
        )
        let entry = await engine.createEntry(name: "GH_PAT", scope: "github/*", tier: .cool)
        #expect(entry.lastRotated == fixedNow)
        let expectedDue = fixedNow.addingTimeInterval(720 * 3600)
        #expect(abs(entry.rotationDue.timeIntervalSince(expectedDue)) < 1)
        #expect(entry.usageState == .cool)
    }

    @Test("on success → updates last_rotated, recomputes rotation_due, op=rotate audit row")
    func test_vaultEntry_onSuccessfulRotation_updatesLastRotated_recomputesRotationDue_appendsAuditRowOpRotate() async throws {
        let now0 = Date(timeIntervalSince1970: 1_700_000_000)
        let clockBox = MutableClock(time: now0)
        let audit = AuditWriter()
        let engine = RotationEngine(
            clock: RotationClock(now: { clockBox.get() }),
            audit: audit,
            seams: SeamsWriter(),
            registry: TokenRegistry()
        )
        let entry = await engine.createEntry(name: "OVH_APP", scope: "ovh/*", tier: .hot)
        // Advance clock 2h; rotate.
        clockBox.set(now0.addingTimeInterval(7200))
        // Non-zero fetch counters to avoid triggering dormancy → distantFuture.
        await engine.setFetchCounters(secret: "OVH_APP", f24h: 1, f7d: 0, f30d: 0)
        let rotated = try await engine.applyRotation(entry: entry)
        #expect(rotated.lastRotated == clockBox.get())
        #expect(rotated.rotationDue > rotated.lastRotated)

        let rows = await audit.all()
        let opRotateRow = try #require(rows.first { $0.op == .rotate && $0.allow == .allow })
        #expect(opRotateRow.secretName == "OVH_APP")
        #expect(opRotateRow.reason == nil)
    }

    @Test("on failure → does not update last_rotated, appends deny row, enqueues retry")
    func test_vaultEntry_onRotationFailure_doesNotUpdateLastRotated_appendsDenyRow_enqueuesRetry() async throws {
        let fixedNow = Date(timeIntervalSince1970: 1_700_000_000)
        let audit = AuditWriter()
        let engine = RotationEngine(
            clock: RotationClock(now: { fixedNow }),
            audit: audit,
            seams: SeamsWriter(),
            registry: TokenRegistry()
        )
        let entry = await engine.createEntry(name: "FAIL_KEY", scope: "ovh/*", tier: .hot)
        let before = entry.lastRotated
        try await engine.handleFailure(entry: entry, reason: "vendor 500")
        let after = await engine.entry(name: "FAIL_KEY")
        #expect(after?.lastRotated == before)

        let rows = await audit.all()
        let deny = try #require(rows.first)
        #expect(deny.allow == .deny)
        #expect(deny.reason == .rotationFailed)

        let retryDue = await engine.retryDueDate(secret: "FAIL_KEY")
        #expect(retryDue == fixedNow.addingTimeInterval(300))
    }

    @Test("retired → archived with timestamp, never hard-deleted")
    func test_vaultEntry_retired_markedArchivedWithTimestamp_neverHardDeleted() async {
        let fixedNow = Date(timeIntervalSince1970: 1_700_000_000)
        let engine = RotationEngine(
            clock: RotationClock(now: { fixedNow }),
            audit: AuditWriter(),
            seams: SeamsWriter(),
            registry: TokenRegistry()
        )
        _ = await engine.createEntry(name: "OLD", scope: "ovh/*", tier: .warm)
        let archived = await engine.archive(name: "OLD")
        #expect(archived?.usageState == .archived)
        #expect(archived?.rotationDue == fixedNow)
        // Still present in entry storage (not hard-deleted).
        #expect(await engine.entry(name: "OLD") != nil)
        #expect(await engine.entryCount() == 1)
    }

    @Test("usage_state=archived → token issuance refused")
    func test_vaultEntry_usageStateArchived_tokenIssuanceRefused() async {
        let engine = RotationEngine(
            audit: AuditWriter(),
            seams: SeamsWriter(),
            registry: TokenRegistry()
        )
        _ = await engine.createEntry(name: "GONE", scope: "ovh/*", tier: .hot)
        _ = await engine.archive(name: "GONE")
        let archived = try! #require(await engine.entry(name: "GONE"))
        await #expect(throws: RotationEngine.RotationError.archivedEntryIssuanceRefused(name: "GONE")) {
            _ = try await engine.applyRotation(entry: archived)
        }
    }
}
