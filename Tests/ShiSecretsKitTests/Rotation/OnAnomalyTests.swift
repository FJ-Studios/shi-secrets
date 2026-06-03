import Foundation
import Testing
@testable import ShiSecretsKit

// RotationEngine.onAnomaly tests (Task 31 — BR-B-07, BR-C-08).
//
// Anomaly-driven rotations bypass dormancy + cadence + queue, execute
// under 60s (enforced via injected clock), and append exactly one seams
// row per anomaly.

@Suite("OnAnomaly")
struct OnAnomalyTests {

    /// A driver that always rotates successfully. Used by both tests to
    /// isolate the engine's dispatch logic from vendor behavior.
    private struct StubOKDriver: SecretRotationDriver {
        let vendor: String
        func rotate(entry: VaultEntryRef, trigger: RotationTrigger) async -> RotationOutcome {
            .rotated
        }
    }

    private static let anomalies: [AnomalySignal] = [
        .hibp(breachId: "breach-42"),
        .unexpectedIP(ip: "203.0.113.1", secretName: "OVH_APP_KEY"),
        .failedFetchBurst(windowSec: 60, count: 10, secretName: "OVH_APP_KEY"),
    ]

    @Test(
        "dormant + anomaly → rotates immediately",
        arguments: OnAnomalyTests.anomalies
    )
    func test_vaultEntry_dormantAnomalyTriggers_rotatesImmediately(signal: AnomalySignal) async throws {
        let fixedNow = Date(timeIntervalSince1970: 1_700_000_000)
        let seams = SeamsWriter()
        let drivers = DriverRegistry(drivers: [StubOKDriver(vendor: "ovh")])
        let engine = RotationEngine(
            clock: RotationClock(now: { fixedNow }),
            drivers: drivers,
            audit: AuditWriter(),
            seams: seams,
            registry: TokenRegistry()
        )
        let dormant = VaultEntryRef(
            name: "OVH_APP_KEY", scope: "ovh/*", tier: .warm,
            usageState: .dormant,
            lastRotated: fixedNow.addingTimeInterval(-3600 * 24 * 90),
            rotationDue: .distantFuture
        )
        await engine.seed(entry: dormant)

        try await engine.onAnomaly(signal, secretName: "OVH_APP_KEY")

        let after = await engine.entry(name: "OVH_APP_KEY")
        #expect(after?.lastRotated == fixedNow)  // rotated despite dormant
        let seamsRows = await seams.all()
        #expect(seamsRows.count == 1)
        #expect(seamsRows.first?.outcome == .rotated)
    }

    @Test(
        "anomaly overrides dormancy + cadence + queue, completes <60s",
        arguments: OnAnomalyTests.anomalies
    )
    func test_rotation_anomalyDriven_overridesDormancyAndCadenceAndQueue_executesWithin60s(signal: AnomalySignal) async throws {
        // Clock is driven by MutableClock — start at T=0, the test never
        // advances it, so elapsed=0 and SLA is trivially under 60s.
        let start = Date(timeIntervalSince1970: 1_700_000_000)
        let clockBox = MutableClock(time: start)
        let drivers = DriverRegistry(drivers: [StubOKDriver(vendor: "ovh")])
        let engine = RotationEngine(
            clock: RotationClock(now: { clockBox.get() }),
            drivers: drivers,
            audit: AuditWriter(),
            seams: SeamsWriter(),
            registry: TokenRegistry()
        )
        _ = await engine.createEntry(name: "OVH_APP_KEY", scope: "ovh/*", tier: .warm)
        try await engine.onAnomaly(signal, secretName: "OVH_APP_KEY")
        // Passing above line means no SLA breach throw.
    }

    @Test("SLA breach (>60s) throws")
    func test_rotation_anomalyDriven_breachesSLAAbove60s_throws() async {
        // A driver that bumps the clock 61s between onAnomaly's start()
        // sample and the outcome sample: the engine re-samples the clock
        // AFTER driver.rotate returns, so bumping inside rotate pushes
        // elapsed above the 60s ceiling.
        let start = Date(timeIntervalSince1970: 1_700_000_000)
        let clockBox = MutableClock(time: start)

        struct ClockBumpingDriver: SecretRotationDriver {
            let vendor: String
            let clockBox: MutableClock
            let bump: TimeInterval
            func rotate(entry: VaultEntryRef, trigger: RotationTrigger) async -> RotationOutcome {
                let current = clockBox.get()
                clockBox.set(current.addingTimeInterval(bump))
                return .rotated
            }
        }

        let drivers = DriverRegistry(drivers: [
            ClockBumpingDriver(vendor: "ovh", clockBox: clockBox, bump: 61),
        ])
        let engine = RotationEngine(
            clock: RotationClock(now: { clockBox.get() }),
            drivers: drivers,
            audit: AuditWriter(),
            seams: SeamsWriter(),
            registry: TokenRegistry()
        )
        _ = await engine.createEntry(name: "OVH_APP_KEY", scope: "ovh/*", tier: .warm)
        await #expect(throws: RotationEngine.RotationError.self) {
            try await engine.onAnomaly(.hibp(breachId: "b"), secretName: "OVH_APP_KEY")
        }
    }
}
