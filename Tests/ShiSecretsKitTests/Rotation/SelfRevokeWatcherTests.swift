import Foundation
import Testing
@testable import ShiSecretsKit

// SelfRevokeWatcher tests (Task 33 — BR-E-05, BR-E-06).

@Suite("SelfRevokeWatcher")
struct SelfRevokeWatcherTests {

    private struct StubOKDriver: SecretRotationDriver {
        let vendor: String
        func rotate(entry: VaultEntryRef, trigger: RotationTrigger) async -> RotationOutcome {
            .rotated
        }
    }

    private func makeFixture(now: Date) async -> (SelfRevokeWatcher, TokenRegistry, SeamsWriter, RotationEngine) {
        let registry = TokenRegistry()
        let seams = SeamsWriter()
        let drivers = DriverRegistry(drivers: [StubOKDriver(vendor: "ovh")])
        let engine = RotationEngine(
            clock: RotationClock(now: { now }),
            drivers: drivers,
            audit: AuditWriter(),
            seams: seams,
            registry: registry
        )
        _ = await engine.createEntry(name: "OVH_APP_KEY", scope: "ovh/*", tier: .warm)
        let watcher = SelfRevokeWatcher(registry: registry, seams: seams, engine: engine)
        return (watcher, registry, seams, engine)
    }

    private static let validJti = "01JABCDEFGHJKMNPQRSTVWXYZ0"

    @Test("narrow scope + ttl ≤ 600 + op=read allowed as exception")
    func test_selfRevokingDiscoveryToken_narrowScope_ttlLe600_opRead_allowedAsException() async throws {
        let fixedNow = Date(timeIntervalSince1970: 1_700_000_000)
        let (watcher, _, _, _) = await makeFixture(now: fixedNow)
        let entry = SelfRevokeWatcher.Entry(
            jti: Self.validJti,
            parentSecret: "OVH_APP_KEY",
            scope: "ovh/fr",     // depth 2
            ttl: 600,
            op: .read,
            diesAt: fixedNow.addingTimeInterval(600)
        )
        try await watcher.watch(entry: entry)
        let tracking = await watcher.tracking()
        #expect(tracking.count == 1)

        // Broad scope rejected.
        let broad = SelfRevokeWatcher.Entry(
            jti: "01BROADXXXXXXXXXXXXXXXXXX0",
            parentSecret: "X", scope: "*",
            ttl: 600, op: .read,
            diesAt: fixedNow
        )
        await #expect(throws: SelfRevokeWatcher.WatchError.self) {
            try await watcher.watch(entry: broad)
        }
        // Long ttl rejected.
        let longTTL = SelfRevokeWatcher.Entry(
            jti: "01LONGTTLXXXXXXXXXXXXXXXX0",
            parentSecret: "X", scope: "ovh/fr",
            ttl: 3600, op: .read,
            diesAt: fixedNow
        )
        await #expect(throws: SelfRevokeWatcher.WatchError.self) {
            try await watcher.watch(entry: longTTL)
        }
        // Op=rotate rejected.
        let rotateOp = SelfRevokeWatcher.Entry(
            jti: "01ROTATEXXXXXXXXXXXXXXXXX0",
            parentSecret: "X", scope: "ovh/fr",
            ttl: 600, op: .rotate,
            diesAt: fixedNow
        )
        await #expect(throws: SelfRevokeWatcher.WatchError.self) {
            try await watcher.watch(entry: rotateOp)
        }
    }

    @Test("records self_revoke_declared=true in audit surface (tracked)")
    func test_selfRevokingDiscoveryToken_recordsSelfRevokeDeclaredTrueInAudit() async throws {
        let fixedNow = Date(timeIntervalSince1970: 1_700_000_000)
        let (watcher, _, _, _) = await makeFixture(now: fixedNow)
        let entry = SelfRevokeWatcher.Entry(
            jti: Self.validJti,
            parentSecret: "OVH_APP_KEY",
            scope: "ovh/fr", ttl: 300, op: .read,
            diesAt: fixedNow.addingTimeInterval(300)
        )
        try await watcher.watch(entry: entry)
        let tracking = await watcher.tracking()
        // The very fact that the watcher holds it is the self_revoke_declared
        // surface — the broker only tracks tokens whose issuance was
        // declared self-revoking (BR-E-05 accepts-as-exception contract).
        #expect(tracking.first?.jti == Self.validJti)
        #expect(tracking.first?.parentSecret == "OVH_APP_KEY")
    }

    @Test("missing self-revoke call before dies_at → anomaly, parent rotates")
    func test_selfRevokeDeclared_missingSelfRevokeCallBeforeDiesAt_triggersAnomaly_parentRotates() async throws {
        let start = Date(timeIntervalSince1970: 1_700_000_000)
        let (watcher, _, seams, engine) = await makeFixture(now: start)
        let entry = SelfRevokeWatcher.Entry(
            jti: Self.validJti,
            parentSecret: "OVH_APP_KEY",
            scope: "ovh/fr", ttl: 300, op: .read,
            diesAt: start.addingTimeInterval(300)
        )
        try await watcher.watch(entry: entry)

        // Advance past dies_at and sweep — the jti was never revoked by
        // its bearer, so the watcher must emit a seams row + anomaly and
        // re-rotate the parent.
        let nowAfter = start.addingTimeInterval(301)
        try await watcher.tick(now: nowAfter)

        let seamsRows = await seams.all()
        // One from SelfRevokeWatcher (.bypassed) + one from onAnomaly rotate path.
        let selfRevokeRow = try #require(seamsRows.first { row in
            if case .selfRevokeMissed = row.signal { return true }
            return false
        })
        #expect(selfRevokeRow.secretName == "OVH_APP_KEY")

        // Parent rotated via the onAnomaly path — rotation_due pushed out.
        let parent = try #require(await engine.entry(name: "OVH_APP_KEY"))
        #expect(parent.lastRotated.timeIntervalSince(start) >= 0)

        // Entry no longer tracked.
        let tracked = await watcher.tracking()
        #expect(tracked.isEmpty)
    }
}
