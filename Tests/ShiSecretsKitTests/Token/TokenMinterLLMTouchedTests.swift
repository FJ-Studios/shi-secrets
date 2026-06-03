import Crypto
import Foundation
import Testing
@testable import ShiSecretsKit

// TokenMinter llm_touched + TTL tests (Task 18 — BR-A-13, BR-E-01, BR-H-03, BR-D-04).
//
// llm_touched is set by the broker server-side from transport metadata
// ONLY; any caller-supplied value is ignored. TTL is capped at 3600s
// (BR-A-03); a requested TTL above 3600 is rejected outright.

@Suite("TokenMinterLLMTouched")
struct TokenMinterLLMTouchedTests {

    /// Review finding U15 — MCP transport MUST include a toolName. The
    /// signed manifest entry below mirrors the production `mcp-manifest.json`
    /// op-gate (BR-H-05) so tests exercise the transport-driven llm_touched
    /// path without tripping on `.toolNameRequiredForMCP`.
    private static let mcpToolEntry = ManifestVerifier.ToolEntry(
        toolName: "secrets.request_token",
        schemaHash: "sha256:test",
        scopeGlob: "ovh/*",
        maxTtl: 3600,
        op: .read
    )

    private func makeMinter(tools: [ManifestVerifier.ToolEntry] = [Self.mcpToolEntry]) -> TokenMinter {
        let signingKey = Curve25519.Signing.PrivateKey()
        return TokenMinter(
            registry: TokenRegistry(),
            signingKey: signingKey,
            toolManifest: tools
        )
    }

    @Test("llm_touched set by broker server-side from transport — caller value ignored")
    func token_llmTouchedInClaim_setByBrokerServerSide_callerValueIgnored() async throws {
        let minter = makeMinter()
        // MCP transport ALWAYS sets llm_touched=true regardless of
        // anything the caller might try to smuggle in the request.
        let token = try await minter.mint(
            request: .init(sub: "bot:x", scope: "ovh/*", op: .read, ttl: 600, toolName: "secrets.request_token"),
            transport: .mcp,
            peerUid: nil
        )
        #expect(token.claims.llmTouched == true)

        // Unix transport defaults to false; toolName optional for non-MCP.
        let unixToken = try await minter.mint(
            request: .init(sub: "bot:x", scope: "ovh/*", op: .read, ttl: 600, toolName: nil),
            transport: .unix,
            peerUid: 1001
        )
        #expect(unixToken.claims.llmTouched == false)
    }

    @Test("llm_touched=true forces TTL ≤ 3600")
    func llmTouchedToken_ttlCappedAt3600() async throws {
        let minter = makeMinter()
        let token = try await minter.mint(
            request: .init(sub: "bot:x", scope: "ovh/*", op: .read, ttl: 3600, toolName: "secrets.request_token"),
            transport: .mcp,
            peerUid: nil
        )
        #expect(token.claims.ttl == 3600)
        #expect(token.claims.llmTouched == true)
    }

    @Test("llm_touched=true with ttl > 3600 rejected")
    func llmTouchedToken_ttlAbove3600_rejected() async throws {
        let minter = makeMinter()
        await #expect(throws: ShikkiSBT.Error.self) {
            _ = try await minter.mint(
                request: .init(sub: "bot:x", scope: "ovh/*", op: .read, ttl: 7200, toolName: "secrets.request_token"),
                transport: .mcp,
                peerUid: nil
            )
        }
    }

    @Test("broker ignores llm_touched in caller payload — sets from transport metadata only")
    func broker_ignoresLlmTouchedInCallerPayload_setsFromTransportMetadataOnly() async throws {
        // The Request type has NO `llmTouched` field — the absence at the
        // type level enforces BR-H-03 by construction. We assert the
        // transport-driven flag here.
        let minter = makeMinter()
        let mcp = try await minter.mint(
            request: .init(sub: "bot:x", scope: "ovh/*", op: .read, ttl: 600, toolName: "secrets.request_token"),
            transport: .mcp,
            peerUid: nil
        )
        #expect(mcp.claims.llmTouched == true)
        let unix = try await minter.mint(
            request: .init(sub: "bot:x", scope: "ovh/*", op: .read, ttl: 600, toolName: nil),
            transport: .unix,
            peerUid: 1001
        )
        #expect(unix.claims.llmTouched == false)
    }

    @Test("MCP transport without toolName is refused — U15")
    func mcp_withoutToolName_refused_U15() async throws {
        let minter = makeMinter()
        await #expect(throws: TokenMinter.MintError.toolNameRequiredForMCP) {
            _ = try await minter.mint(
                request: .init(sub: "bot:x", scope: "ovh/*", op: .read, ttl: 600, toolName: nil),
                transport: .mcp,
                peerUid: nil
            )
        }
    }
}
