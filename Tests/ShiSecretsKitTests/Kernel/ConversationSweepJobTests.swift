import Foundation
import Testing
@testable import ShiSecretsKit

// ConversationSweepJob tests (Task 39 — BR-C-07, BR-E-03).

@Suite("ConversationSweepJob")
struct ConversationSweepJobTests {

    private struct OKDriver: SecretRotationDriver {
        let vendor: String
        func rotate(entry: VaultEntryRef, trigger: RotationTrigger) async -> RotationOutcome { .rotated }
    }

    private func fixture() async -> (RotationEngine, ActiveSessions, ConversationSweepJob) {
        let drivers = DriverRegistry(drivers: [OKDriver(vendor: "ovh")])
        let engine = RotationEngine(
            drivers: drivers,
            audit: AuditWriter(),
            seams: SeamsWriter(),
            registry: TokenRegistry()
        )
        _ = await engine.createEntry(name: "OVH_APP_KEY", scope: "ovh/*", tier: .warm)
        let sessions = ActiveSessions()
        let job = ConversationSweepJob(engine: engine, activeSessions: sessions)
        return (engine, sessions, job)
    }

    @Test("sweep interval at least 15 minutes (≤900s)")
    func test_rotation_sweepIntervalAtLeast15Minutes() {
        // The constant cap per BR-C-07: interval MUST not exceed 900s.
        #expect(ConversationSweepJob.maxSweepIntervalSeconds <= 900)
        let (_, _, job) = asyncFixture()
        switch job.schedule {
        case .interval(let s):
            #expect(s <= 900)
        case .onEvent:
            Issue.record("sweep must be interval-scheduled")
        }
    }

    @Test("conversation end detected via 15-min cron sweep fires queued rotation")
    func test_rotation_conversationEnd_detectedVia15MinCronSweep_firesQueuedRotation() async throws {
        let (engine, sessions, job) = await fixture()
        await engine.onLLMTouched(secret: "OVH_APP_KEY", sessionId: "sid-A")
        await sessions.add("sid-A")
        // Before: queue has one entry.
        #expect(await engine.llmQueuedParents(sessionId: "sid-A").count == 1)

        try await job.run()

        // After: queue empty, parent rotated.
        #expect(await engine.llmQueuedParents(sessionId: "sid-A").isEmpty)
        #expect(await sessions.count() == 0)
    }

    @Test("conversation end detected via session end hook fires queued rotation")
    func test_rotation_conversationEnd_detectedViaSessionEndHook_firesQueuedRotation() async throws {
        let (engine, sessions, job) = await fixture()
        await engine.onLLMTouched(secret: "OVH_APP_KEY", sessionId: "sid-B")
        await sessions.add("sid-B")
        try await job.onSessionEnd(sessionId: "sid-B")
        #expect(await engine.llmQueuedParents(sessionId: "sid-B").isEmpty)
        #expect(await sessions.count() == 0)
    }

    @Test("conversation end via cron sweep 15-min signaled")
    func test_conversationEnd_viaCronSweep15Min_signalled() async throws {
        // Alias for the 15-min cron path — asserts cap is honored.
        let (engine, sessions, job) = await fixture()
        await engine.onLLMTouched(secret: "OVH_APP_KEY", sessionId: "sid-C")
        await sessions.add("sid-C")
        try await job.run()
        switch job.schedule {
        case .interval(let s): #expect(s == ConversationSweepJob.maxSweepIntervalSeconds)
        case .onEvent:         Issue.record("cron path must be interval")
        }
        #expect(await engine.llmQueuedParents(sessionId: "sid-C").isEmpty)
    }

    @Test("conversation end via session end hook signaled")
    func test_conversationEnd_viaSessionEndHook_signalled() async throws {
        let (engine, sessions, job) = await fixture()
        await engine.onLLMTouched(secret: "OVH_APP_KEY", sessionId: "sid-D")
        await sessions.add("sid-D")
        try await job.onSessionEnd(sessionId: "sid-D")
        #expect(await engine.llmQueuedParents(sessionId: "sid-D").isEmpty)
    }

    // Hack so the schedule-constant test can be purely sync.
    private func asyncFixture() -> (RotationEngine, ActiveSessions, ConversationSweepJob) {
        let engine = RotationEngine(
            audit: AuditWriter(),
            seams: SeamsWriter(),
            registry: TokenRegistry()
        )
        let sessions = ActiveSessions()
        let job = ConversationSweepJob(engine: engine, activeSessions: sessions)
        return (engine, sessions, job)
    }
}
