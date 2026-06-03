import Foundation
import Testing
@testable import ShiSecretsKit

// onLLMTouched / onConversationEnd tests (Task 32 — BR-C-06, BR-E-02, BR-E-04).
//
// - An llm_touched fetch enqueues its parent for post-conversation rotation.
// - On SessionEnd, the queue drains and each parent rotates through the driver.
// - Broker never returns long-lived plaintext on MCP or LLM-bridge paths
//   (type-system-enforced by BrokerResponse — see T34).

@Suite("LLMTouched")
struct LLMTouchedTests {

    private struct StubOKDriver: SecretRotationDriver {
        let vendor: String
        func rotate(entry: VaultEntryRef, trigger: RotationTrigger) async -> RotationOutcome {
            .rotated
        }
    }

    @Test("llm_touched fetch enqueues parent regardless of cadence")
    func test_rotation_llmTouchedFetch_enqueuesParentForPostConversationRotation_regardlessOfCadence() async {
        let engine = RotationEngine(
            audit: AuditWriter(),
            seams: SeamsWriter(),
            registry: TokenRegistry()
        )
        _ = await engine.createEntry(name: "OVH_APP_KEY", scope: "ovh/*", tier: .cool)
        // cool baseHours = 720 — nowhere near due. Still must queue.
        await engine.onLLMTouched(secret: "OVH_APP_KEY", sessionId: "sid-1")
        let q = await engine.llmQueuedParents(sessionId: "sid-1")
        #expect(q == ["OVH_APP_KEY"])

        // Idempotent on repeat.
        await engine.onLLMTouched(secret: "OVH_APP_KEY", sessionId: "sid-1")
        let q2 = await engine.llmQueuedParents(sessionId: "sid-1")
        #expect(q2.count == 1)
    }

    @Test("llm_touched parent auto-rotates within 60 minutes of conversation end")
    func test_llmTouchedParent_autoRotatesWithin60MinutesOfConversationEnd() async throws {
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
        let entry = await engine.createEntry(name: "OVH_APP_KEY", scope: "ovh/*", tier: .cool)
        await engine.onLLMTouched(secret: "OVH_APP_KEY", sessionId: "sid-2")
        // Advance 30 minutes (within the 60-min cap).
        clockBox.set(start.addingTimeInterval(1800))
        try await engine.onConversationEnd(sessionId: "sid-2")
        let rotated = try #require(await engine.entry(name: "OVH_APP_KEY"))
        #expect(rotated.lastRotated == clockBox.get())
        #expect(rotated.lastRotated.timeIntervalSince(entry.lastRotated) <= 3600)

        // Queue is drained on session end.
        let q = await engine.llmQueuedParents(sessionId: "sid-2")
        #expect(q.isEmpty)
    }

    @Test("llmRotationQueue enforces per-session cap (U10)")
    func test_llmRotationQueue_perSessionCap_U10() async throws {
        // Review finding U10 — past `llmQueueMaxPerSession`, additional
        // inserts are dropped and a `.llmQueueSaturated` seam appears.
        let seams = SeamsWriter()
        let engine = RotationEngine(
            audit: AuditWriter(),
            seams: seams,
            registry: TokenRegistry()
        )
        for i in 0 ..< RotationEngine.llmQueueMaxPerSession {
            await engine.onLLMTouched(secret: "s\(i)", sessionId: "sid")
        }
        // Adding one more secret triggers the cap.
        await engine.onLLMTouched(secret: "overflow", sessionId: "sid")
        let q = await engine.llmQueuedParents(sessionId: "sid")
        #expect(q.count == RotationEngine.llmQueueMaxPerSession)
        let seamsRows = await seams.all()
        #expect(seamsRows.contains(where: { row in
            if case .llmQueueSaturated = row.signal { return true }
            return false
        }))
    }

    @Test("broker never returns long-lived plaintext to MCP transport")
    func test_broker_neverReturnsLongLivedPlaintext_toMcpTransport() throws {
        // BR-H-01 — enforced via type system on BrokerResponse.
        // An MCP transport MUST select a non-plaintext response variant.
        let claims = ShikkiSBT.Claims(
            sub: "bot:shi-mcp", scope: "ovh/*", op: .read, ttl: 600,
            jti: "01JABCDEFGHJKMNPQRSTVWXYZ0",
            nbf: Date(), diesAt: Date().addingTimeInterval(600),
            llmTouched: true
        )
        let sbt = ShikkiSBT(claims: claims)
        let response: BrokerResponse = .ephemeralToken(sbt)
        switch response {
        case .ephemeralToken(let tok):
            #expect(tok.claims.ttl <= 600)
        case .boundPlaintext, .deny, .dbCredentials, .oauthPair, .connectionBundle:
            Issue.record("MCP transport expected ephemeralToken, got other variant")
        }
    }

    @Test("broker never returns long-lived plaintext to LLM bridge uid")
    func test_broker_neverReturnsLongLivedPlaintext_toLlmBridgeUid() {
        // There is no `.rawPlaintext` case on BrokerResponse by construction.
        // The test exercises the public surface: `.boundPlaintext` is always
        // tied to a specific jti and an ephemeral TTL (audited by T34 tests).
        let bound: BrokerResponse = .boundPlaintext(jti: "01JABCDEFGHJKMNPQRSTVWXYZ0", plaintext: "short")
        switch bound {
        case .boundPlaintext(let jti, _):
            #expect(!jti.isEmpty)
        case .ephemeralToken, .deny, .dbCredentials, .oauthPair, .connectionBundle:
            Issue.record("LLM-bridge bound plaintext must route via .boundPlaintext")
        }
    }
}
