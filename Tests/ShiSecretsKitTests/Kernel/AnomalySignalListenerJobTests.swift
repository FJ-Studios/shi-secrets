import Foundation
import Testing
@testable import ShiSecretsKit

// AnomalySignalListenerJob tests (Task 38 — BR-C-08).

@Suite("AnomalySignalListenerJob")
struct AnomalySignalListenerJobTests {

    private struct OKDriver: SecretRotationDriver {
        let vendor: String
        func rotate(entry: VaultEntryRef, trigger: RotationTrigger) async -> RotationOutcome { .rotated }
    }

    @Test("listener subscribes to shikki.secrets.anomaly and invokes onAnomaly within 60s")
    func test_anomalyListener_subscribesToShiSecretsAnomalyChannel_invokesOnAnomalyWithin60s() async throws {
        let fixedNow = Date(timeIntervalSince1970: 1_700_000_000)
        let seams = SeamsWriter()
        let drivers = DriverRegistry(drivers: [OKDriver(vendor: "ovh")])
        let engine = RotationEngine(
            clock: RotationClock(now: { fixedNow }),
            drivers: drivers,
            audit: AuditWriter(),
            seams: seams,
            registry: TokenRegistry()
        )
        _ = await engine.createEntry(name: "OVH_APP_KEY", scope: "ovh/*", tier: .warm)

        let staging = AnomalyStaging()
        await staging.push(
            AnomalyStaging.Payload(
                signal: .hibp(breachId: "b"),
                secretName: "OVH_APP_KEY"
            )
        )
        let job = AnomalySignalListenerJob(engine: engine, staging: staging)
        #expect(job.jobId == "secrets.anomaly.listener")
        #expect(job.qos == .hot)
        #expect(job.schedule == .onEvent("shikki.secrets.anomaly"))

        try await job.run()

        let rows = await seams.all()
        #expect(rows.contains { $0.outcome == .rotated })
        #expect(await staging.count() == 0)
    }
}
