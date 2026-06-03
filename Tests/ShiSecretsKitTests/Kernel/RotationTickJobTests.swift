import Foundation
import Testing
@testable import ShiSecretsKit

// RotationTickJob tests (Task 37 — BR-C-0X).

@Suite("RotationTickJob")
struct RotationTickJobTests {

    @Test(
        "one kernel job per tier × QoS track",
        arguments: [QoSTrackTier.hot, .warm, .cool, .external]
    )
    func test_rotation_oneKernelJobPerTierQoSTrack(tier: QoSTrackTier) {
        let engine = RotationEngine(
            audit: AuditWriter(),
            seams: SeamsWriter(),
            registry: TokenRegistry()
        )
        let job = RotationTickJob(track: tier, engine: engine)
        #expect(job.jobId == "secrets.rotation.\(tier.rawValue)")
        switch tier {
        case .hot:      #expect(job.qos == .hot)
        case .warm:     #expect(job.qos == .warm)
        case .cool:     #expect(job.qos == .cool)
        case .external: #expect(job.qos == .external)
        }
        // Schedule is interval-based, values locked by Phase 3 §4.
        switch job.schedule {
        case .interval(let secs):
            switch tier {
            case .hot:      #expect(secs == 300)
            case .warm:     #expect(secs == 1800)
            case .cool:     #expect(secs == 7200)
            case .external: #expect(secs == 21600)
            }
        case .onEvent:
            Issue.record("RotationTickJob must be interval-scheduled")
        }
    }

    @Test("double-failure path emits a seam row (U20)")
    func test_rotationTickJob_doubleFailure_emitsSeamRow_U20() async throws {
        // Review finding U20 — `try?` was swallowing failures inside
        // the already-failure branch. The engine now exposes a helper
        // that RotationTickJob calls when handleFailure itself throws;
        // we exercise the helper directly (crafting a real
        // audit-failure requires a mocked AuditWriter; this test
        // asserts the seam-writing path works in isolation).
        let seams = SeamsWriter()
        let engine = RotationEngine(
            audit: AuditWriter(),
            seams: seams,
            registry: TokenRegistry()
        )
        await engine.seamRotationHandlerDoubleFailure(
            secretName: "OVH_APP_KEY",
            primary: "applyRotation threw",
            secondary: "handleFailure also threw"
        )
        let rows = await seams.all()
        #expect(rows.count == 1)
        #expect(rows.first?.secretName == "OVH_APP_KEY")
        #expect(rows.first?.outcome == .failed)
        #expect(rows.first?.notes?.contains("double-failure") == true)
    }

    @Test("handleFailure ALSO throws — seam emitted with rotationHandlerDoubleFailure signal (T4)")
    func test_rotationTickJob_handleFailureAlsoThrows_emitsSeamRotationHandlerDoubleFailure() async throws {
        // 3rd-pass validator T4 — full double-failure round-trip through
        // RotationTickJob.run():
        //   1) engine.applyRotation throws (audit.append inside it
        //      rejects the 65-char oversized secret_name — the
        //      `PoisonedAuditWriter` path modeled via AuditWriter's
        //      own BR-J-05 guard).
        //   2) engine.handleFailure ALSO throws for the same reason.
        //   3) RotationTickJob falls through to
        //      engine.seamRotationHandlerDoubleFailure(), which emits a
        //      seam row with signal `.rotationHandlerDoubleFailure`
        //      (dedicated case added in this pass; previously
        //      shoehorned onto `.failedFetchBurst(windowSec: 0, ...)`).
        let audit = AuditWriter()
        let seams = SeamsWriter()
        let registry = TokenRegistry()
        let fixedNow = Date(timeIntervalSince1970: 1_700_000_000)
        let engine = RotationEngine(
            clock: RotationClock(now: { fixedNow }),
            audit: audit,
            seams: seams,
            registry: registry
        )
        // 65-char secret name — the `PoisonedAuditWriter` pattern:
        // AuditWriter.append enforces BR-J-05 by rejecting rows with
        // `secretName.count > maxSecretNameLength=64`. Both
        // applyRotation and handleFailure internally write such a row,
        // so both throw; this is the textbook double-failure path.
        let oversizedName = String(repeating: "x", count: 65)
        // Non-archived, non-dormant entry due for rotation — tick()
        // enumerates it, applyRotation attempts + throws, handleFailure
        // attempts + throws, double-failure seam emitted.
        let entry = VaultEntryRef(
            name: oversizedName,
            scope: "ovh/*",
            tier: .hot,
            usageState: .hot,
            lastRotated: fixedNow.addingTimeInterval(-3600),
            rotationDue: fixedNow.addingTimeInterval(-600)
        )
        await engine.seed(entry: entry)

        let job = RotationTickJob(track: .hot, engine: engine)
        try await job.run()

        let rows = await seams.all()
        #expect(rows.count == 1)
        let row = try #require(rows.first)
        #expect(row.outcome == .failed)
        if case .rotationHandlerDoubleFailure(let n, _, _) = row.signal {
            #expect(n == entry.name)
        } else {
            Issue.record("expected .rotationHandlerDoubleFailure, got \(row.signal)")
        }
        #expect(row.notes?.contains("double-failure") == true)
        // No audit row made it through — both appends were rejected.
        let auditRows = await audit.all()
        #expect(auditRows.isEmpty)
    }

    @Test("rotation tick job invokes engine tick for declared tier")
    func test_rotationTickJob_invokesEngineTickForDeclaredTier() async throws {
        let fixedNow = Date(timeIntervalSince1970: 1_700_000_000)
        let engine = RotationEngine(
            clock: RotationClock(now: { fixedNow }),
            audit: AuditWriter(),
            seams: SeamsWriter(),
            registry: TokenRegistry()
        )
        // Seed an overdue hot entry; tick should enumerate + apply.
        let entry = VaultEntryRef(
            name: "HOT_DUE", scope: "ovh/*", tier: .hot,
            usageState: .hot,
            lastRotated: fixedNow.addingTimeInterval(-3600 * 48),
            rotationDue: fixedNow.addingTimeInterval(-3600)
        )
        await engine.seed(entry: entry)
        await engine.setFetchCounters(secret: "HOT_DUE", f24h: 1, f7d: 0, f30d: 0)

        let job = RotationTickJob(track: .hot, engine: engine)
        try await job.run()

        let after = try #require(await engine.entry(name: "HOT_DUE"))
        // Last-rotated advanced to `now`.
        #expect(after.lastRotated == fixedNow)
    }
}
