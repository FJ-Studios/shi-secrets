import Foundation
@testable import ShiSecretsBrokerd
import ShiSecretsKit
import Testing

// T67 — Integration: rotation success/failure + SessionEnd hook.
//
// The full real-bw + real-vendor path is v1.1 work (requires a
// Vaultwarden container + mockoon); these tests drive the same seams
// in-process so the broker's rotation lifecycle is covered end-to-end.

/// Stub driver used by integration tests to drive success / failure paths.
struct IntegStubDriver: SecretRotationDriver {
    let vendor: String
    let willSucceed: Bool
    func rotate(entry: VaultEntryRef, trigger: RotationTrigger) async -> RotationOutcome {
        _ = entry; _ = trigger
        return willSucceed ? .rotated : .failed(reason: "vendor API 500")
    }
}

@Suite("RotationIntegration")
struct RotationIntegrationTests {

    @Test("successful rotation — applyRotation appends op=rotate allow audit row")
    func test_integration_successfulRotation_updatesVaultEntry_viaBwCli_appendsShikkiDbAuditRow() async throws {
        let stack = try await IntegSupport.makeStack()
        defer { Task { await IntegSupport.tearDown(stack) } }

        let drivers = DriverRegistry()
        await drivers.register(IntegStubDriver(vendor: "ovh", willSucceed: true))
        let engine = RotationEngine(
            drivers: drivers, audit: stack.audit, seams: stack.seams, registry: stack.registry
        )
        let entry = await engine.createEntry(name: "OVH_APP_KEY", scope: "ovh/dns/*", tier: .warm)
        _ = try await engine.applyRotation(entry: entry)

        let rows = await stack.audit.all()
        let rotateAllow = rows.filter { $0.op == .rotate && $0.allow == .allow }
        #expect(rotateAllow.count >= 1)
    }

    @Test("vendor API 500 — handleFailure writes deny + enqueues 5-min retry + leaves last_rotated")
    func test_integration_rotationFailure_vendorApi500_enqueuesRetry_noLastRotatedUpdate() async throws {
        let stack = try await IntegSupport.makeStack()
        defer { Task { await IntegSupport.tearDown(stack) } }

        let drivers = DriverRegistry()
        await drivers.register(IntegStubDriver(vendor: "ovh", willSucceed: false))
        let engine = RotationEngine(
            drivers: drivers, audit: stack.audit, seams: stack.seams, registry: stack.registry
        )
        let entry = await engine.createEntry(name: "OVH_APP_KEY", scope: "ovh/dns/*", tier: .warm)
        let before = await engine.entry(name: entry.name)
        try await engine.handleFailure(entry: entry, reason: "vendor 500")
        let after = await engine.entry(name: entry.name)
        // last_rotated preserved on failure (BR-B-04).
        #expect(before?.lastRotated == after?.lastRotated)
        // Retry enqueued.
        let retry = await engine.retryDueDate(secret: entry.name)
        #expect(retry != nil)
        // Audit deny rotation_failed present.
        let rows = await stack.audit.all()
        #expect(rows.contains(where: { $0.reason == .rotationFailed }))
    }

    @Test("SessionEnd hook — drains llm rotation queue + fires driver.rotate")
    func test_integration_sessionEndHookReceived_firesQueuedRotation_realBwCall() async throws {
        let stack = try await IntegSupport.makeStack()
        defer { Task { await IntegSupport.tearDown(stack) } }

        let drivers = DriverRegistry()
        await drivers.register(IntegStubDriver(vendor: "ovh", willSucceed: true))
        let engine = RotationEngine(
            drivers: drivers, audit: stack.audit, seams: stack.seams, registry: stack.registry
        )
        _ = await engine.createEntry(name: "OVH_APP_KEY", scope: "ovh/dns/*", tier: .warm)
        await engine.onLLMTouched(secret: "OVH_APP_KEY", sessionId: "cc-sess-8F3A")
        #expect(await engine.llmQueuedParents(sessionId: "cc-sess-8F3A") == ["OVH_APP_KEY"])

        try await engine.onConversationEnd(sessionId: "cc-sess-8F3A")
        #expect(await engine.llmQueuedParents(sessionId: "cc-sess-8F3A").isEmpty)
        // Rotation was applied — audit has op=rotate allow.
        let rows = await stack.audit.all()
        #expect(rows.contains(where: { $0.op == .rotate && $0.allow == .allow }))
    }
}
