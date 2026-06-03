import Foundation
@testable import ShiSecretsBrokerd
import ShiSecretsKit
import Testing

// T73 — E2E: MCP client → bridge → broker → audit row (end-to-end).
//
// Full MCP transport + real MCP clients are v1.1 E2E territory; we
// exercise the full broker behavior by walking the same objects the
// MCP executable would.

@Suite("MCPClientE2E")
struct ClaudeCodeMCPE2ETests {

    @Test("MCP client → shi-mcp → broker mints ephemeral token; SessionEnd auto-revokes within 60 min")
    func test_e2e_claudeCode_to_shiMcp_to_broker_mintsEphemeralToken_ovhDnsRead_sessionEnd_autoRevokesWithin60min() async throws {
        let stack = try await E2ESupport.make()
        defer { Task { await E2ESupport.tearDown(stack) } }

        let resp = try await E2ESupport.claudeMCPRequestToken(
            stack: stack,
            scope: "ovh/dns/read",
            op: .read,
            ttl: 600
        )
        guard case .ephemeralToken(let sbt) = resp else {
            Issue.record("expected ephemeralToken"); return
        }
        // BR-A-03 — TTL ≤ 3600, and BR-E-01 — MCP-transport ≤ 3600.
        #expect(sbt.claims.ttl <= 3600)
        #expect(sbt.claims.llmTouched == true)

        // The llm-touched parent rotation is queued; SessionEnd drains it.
        _ = await stack.engine.createEntry(name: "ovh/dns/read", scope: "ovh/dns/read", tier: .warm)
        await stack.engine.onLLMTouched(secret: "ovh/dns/read", sessionId: "cc-sess-E2E")
        try await stack.engine.onConversationEnd(sessionId: "cc-sess-E2E")
        // Queue drained.
        #expect(await stack.engine.llmQueuedParents(sessionId: "cc-sess-E2E").isEmpty)
    }

    @Test("MCP transport — sets llm_touched=true server-side end-to-end")
    func test_e2e_mcpTransport_setsLlmTouchedTrueServerSide_endToEnd() async throws {
        let stack = try await E2ESupport.make()
        defer { Task { await E2ESupport.tearDown(stack) } }
        let resp = try await E2ESupport.claudeMCPRequestToken(
            stack: stack, scope: "ovh/OVH_APP_KEY", op: .read, ttl: 300
        )
        if case .ephemeralToken(let sbt) = resp {
            #expect(sbt.claims.llmTouched == true)
        } else {
            Issue.record("expected ephemeralToken"); return
        }
        // AuditRow also carries llm_touched=true.
        let rows = await stack.audit.all()
        #expect(rows.contains(where: { $0.llmTouched == true && $0.callerTransport == .mcp }))
    }

    @Test("fetch flow — writes audit row with llm_touched=true visible in audit surface")
    func test_e2e_fetchFlow_writesShikkiEnterpriseAuditRow_llmTouchedTrueVisible() async throws {
        let stack = try await E2ESupport.make()
        defer { Task { await E2ESupport.tearDown(stack) } }
        _ = try await E2ESupport.claudeMCPRequestToken(
            stack: stack, scope: "ovh/OVH_APP_KEY", op: .read, ttl: 300
        )
        let rows = await stack.audit.all()
        let llmRow = rows.last(where: { $0.callerTransport == .mcp })
        #expect(llmRow?.llmTouched == true)
        #expect(llmRow?.allow == .allow)
    }
}
