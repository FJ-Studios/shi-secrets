import Foundation
@testable import ShiSecretsBrokerd
import ShiSecretsKit
import Testing

@Suite("MCPBridge")
struct MCPBridgeTests {

    @Test("MCP caller without bearer is rejected")
    func test_mcp_callerBearerTokenRequired_unauthenticatedRejected() async {
        let bridge = MCPBridge(bearerAllowlist: ["pinned-a"])
        do {
            _ = try await bridge.wrapMcpRequest(payload: Data([0x01]), bearer: nil)
            Issue.record("expected bearerMissing")
        } catch let error as MCPBridgeError {
            #expect(error == .bearerMissing)
        } catch {
            Issue.record("expected MCPBridgeError, got \(error)")
        }
    }

    @Test("valid bearer is accepted and the request is wrapped as transport=.mcp")
    func test_mcp_validBearerToken_accepted() async throws {
        let bridge = MCPBridge(bearerAllowlist: ["pinned-a"])
        let wrapped = try await bridge.wrapMcpRequest(
            payload: Data("hello".utf8),
            bearer: "pinned-a"
        )
        #expect(wrapped.transport == .mcp)
        #expect(wrapped.llmTouched == true)
    }

    @Test("llm_touched is set TRUE server-side from transport type, not from payload")
    func test_mcp_llmTouched_setTrueServerSide_fromTransportType_notFromPayload() async throws {
        let bridge = MCPBridge(bearerAllowlist: ["pinned-a"])
        // Caller tries to send {llm_touched: false} — MUST be ignored.
        let payload = Data(#"{"llm_touched":false}"#.utf8)
        let wrapped = try await bridge.wrapMcpRequest(payload: payload, bearer: "pinned-a")
        #expect(wrapped.llmTouched == true)
    }

    @Test("unix caller not registered as LLM bridge defaults llm_touched=false")
    func test_unix_nonMcpCaller_defaultsLlmTouchedFalse() async {
        let bridge = MCPBridge()
        let wrapped = await bridge.wrapUnixRequest(payload: Data(), peerUid: 1_000)
        #expect(wrapped.transport == .unix)
        #expect(wrapped.llmTouched == false)
    }

    @Test("unix caller registered as LLM bridge uid sets llm_touched=true")
    func test_unix_registeredLlmBridgeUid_setsLlmTouchedTrue() async {
        let bridge = MCPBridge()
        await bridge.registerLLMBridgeUid(2_001)
        let wrapped = await bridge.wrapUnixRequest(payload: Data(), peerUid: 2_001)
        #expect(wrapped.transport == .unix)
        #expect(wrapped.llmTouched == true)
    }
}
