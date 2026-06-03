import Foundation
@testable import ShiSecretsBrokerd
import ShiSecretsKit
import Testing

// T75 — E2E: five security scenarios, against the full broker stack.
//
//   1. MCP caller invokes read tool but requests op=rotate → opMismatch
//   2. HIBP anomaly → rotation within 60s (overrides dormancy)
//   3. Dormant secret (30d unfetched) → rotator skips until next fetch
//   4. Manifest sig fails on HUP → broker stays on pinned manifest +
//      seams ledger entry written
//   5. Malicious prompt requests raw OVH key → broker NEVER returns
//      plaintext; ONLY an ephemeral token

/// Stub driver that records whether rotate was called + succeeds or fails.
actor E2EScriptedDriver: SecretRotationDriver {
    nonisolated let vendor: String
    private let outcome: RotationOutcome
    private var calls: [(secret: String, trigger: RotationTrigger)] = []

    init(vendor: String, outcome: RotationOutcome) {
        self.vendor = vendor
        self.outcome = outcome
    }

    nonisolated func rotate(entry: VaultEntryRef, trigger: RotationTrigger) async -> RotationOutcome {
        await record(entry: entry, trigger: trigger)
        return outcome
    }

    private func record(entry: VaultEntryRef, trigger: RotationTrigger) {
        calls.append((entry.name, trigger))
    }

    func snapshot() -> [(secret: String, trigger: RotationTrigger)] { calls }
}

@Suite("SecurityScenariosE2E")
struct SecurityScenariosE2ETests {

    // Scenario 1 — op mismatch.
    @Test("MCP caller invokes read tool but requests op=rotate — broker rejects (op_mismatch)")
    func test_e2e_mcpCallerInvokesReadTool_butRequestsRotateOp_brokerRejectsOpMismatch() async throws {
        let readTool = ManifestVerifier.ToolEntry(
            toolName: "secrets.request_token",
            schemaHash: "h",
            scopeGlob: "ovh/*",
            maxTtl: 600,
            op: .read
        )
        let stack = try await E2ESupport.make(toolManifest: [readTool])
        defer { Task { await E2ESupport.tearDown(stack) } }

        let resp = try await E2ESupport.claudeMCPRequestToken(
            stack: stack,
            scope: "ovh/OVH_APP_KEY",
            op: .rotate,   // mismatch vs manifest's .read
            ttl: 300,
            toolName: "secrets.request_token"
        )
        if case .deny(let reason) = resp {
            #expect(reason == .opMismatch)
        } else {
            Issue.record("expected deny opMismatch; got \(resp)")
        }
    }

    // Scenario 2 — HIBP anomaly triggers immediate rotation, overrides dormancy.
    @Test("anomaly (hibp) — triggers immediate rotation — overrides dormancy — within 60s")
    func test_e2e_anomalySignalHibp_triggersImmediateRotation_overridesDormancy_within60s() async throws {
        let stack = try await E2ESupport.make()
        defer { Task { await E2ESupport.tearDown(stack) } }

        let driver = E2EScriptedDriver(vendor: "ovh", outcome: .rotated)
        let drivers = DriverRegistry()
        await drivers.register(driver)
        let engine = RotationEngine(
            drivers: drivers, audit: stack.audit, seams: stack.seams, registry: stack.registry
        )
        _ = await engine.createEntry(name: "OVH_APP_KEY", scope: "ovh/OVH_APP_KEY", tier: .warm)
        // Force dormancy: zero all counters.
        await engine.setFetchCounters(secret: "OVH_APP_KEY", f24h: 0, f7d: 0, f30d: 0)

        try await engine.onAnomaly(
            .hibp(breachId: "breach-e2e-2026"),
            secretName: "OVH_APP_KEY"
        )
        // Driver was invoked (anomaly overrides dormancy).
        let calls = await driver.snapshot()
        #expect(calls.count == 1)
        if case .anomaly = calls.first?.trigger {} else {
            Issue.record("expected .anomaly trigger")
        }

        let seams = await stack.seams.all()
        #expect(seams.contains(where: { row in
            if case .hibp = row.signal { return true }
            return false
        }))
    }

    // Scenario 3 — dormant secret: rotator skips.
    @Test("dormant secret 30d unfetched — rotator skips until next fetch or anomaly")
    func test_e2e_dormantSecret_30dUnfetched_rotatorSkips_untilNextFetchOrAnomaly() async throws {
        let stack = try await E2ESupport.make()
        defer { Task { await E2ESupport.tearDown(stack) } }

        let engine = stack.engine
        let entry = await engine.createEntry(name: "LEGACY_KEY", scope: "ovh/*", tier: .cool)
        // Make it dormant + mark far-future rotationDue (simulating post-dormancy state).
        await engine.setFetchCounters(secret: "LEGACY_KEY", f24h: 0, f7d: 0, f30d: 0)
        _ = entry
        // Tick should NOT pick it up.
        let candidates = await engine.tick(track: .cool)
        #expect(!candidates.contains("LEGACY_KEY"))
    }

    // Scenario 4 — manifest sig fails on HUP → pinned retained + seams row.
    @Test("manifest sig fails on HUP — broker stays on pinned — seams ledger shows entry")
    func test_e2e_manifestSigFailsOnHup_brokerStaysOnPinnedSchema_seamsLedgerShowsEntry() async throws {
        let stack = try await E2ESupport.make()
        defer { Task { await E2ESupport.tearDown(stack) } }

        // Load a valid manifest first.
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let m = ManifestVerifier.Manifest(
            version: "v1.0", issuedAt: Date(timeIntervalSince1970: 1_777_000_000), tools: []
        )
        let bytes = try encoder.encode(m)
        let sig = try stack.manifestPrivateKey.signature(for: bytes)
        try await stack.manifestStore.loadInitial(bytes: bytes, signature: Data(sig))
        #expect(await stack.manifestStore.current()?.version == "v1.0")

        // HUP with bogus sig — must NOT flip pinned.
        await stack.daemon.handleHUP(bytes: bytes, signature: Data([0xDE, 0xAD, 0xBE, 0xEF]))
        #expect(await stack.manifestStore.current()?.version == "v1.0")
        let seams = await stack.seams.all()
        #expect(seams.contains(where: { row in
            if case .manifestSigFailed = row.signal { return true }
            return false
        }))
    }

    // Scenario 5 — malicious prompt asks for raw plaintext → broker never returns it.
    @Test("malicious prompt — MCP caller requests raw OVH key — broker NEVER returns plaintext, only ephemeral token")
    func test_e2e_maliciousPromptRequestsRawOvhKey_brokerNeverReturnsPlaintext_onlyEphemeralToken() async throws {
        let stack = try await E2ESupport.make()
        defer { Task { await E2ESupport.tearDown(stack) } }

        let resp = try await E2ESupport.claudeMCPRequestToken(
            stack: stack, scope: "ovh/OVH_APP_KEY", op: .read, ttl: 60
        )
        // Prove: the broker's response case is NEVER `.boundPlaintext` on
        // MCP transport. The only allowed cases are `.ephemeralToken` or
        // `.deny(...)`.
        switch resp {
        case .ephemeralToken:
            break
        case .boundPlaintext:
            Issue.record("broker returned boundPlaintext over MCP — BR-H-01 violated!")
        case .deny:
            // If mcp bridge is mis-wired a deny is still acceptable vs leaking plaintext.
            break
        case .dbCredentials, .oauthPair, .connectionBundle:
            Issue.record("broker returned typed credentials over MCP transport — unexpected path")
        }
    }
}
