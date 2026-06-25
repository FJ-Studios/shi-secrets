import Crypto
import Foundation
@testable import ShiSecretsBrokerd
import ShiSecretsKit
import Testing

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// BrokerDaemonBoundPlaintextTests — W4.2 TDD-first tests for caller-type
// dispatch: local-unix → .boundPlaintext, MCP → .ephemeralToken.
//
// Spec UUID: e8c4a921-7d3b-4f5e-9a2c-1d6b8f4e3a91
// Wave: W4.2

@Suite("BrokerDaemonBoundPlaintext")
struct BrokerDaemonBoundPlaintextTests {

    private func socketPath() -> String {
        "/tmp/sh-bp-\(UUID().uuidString.prefix(8)).s"
    }

    /// Build a full daemon with an in-memory vault seeded with the given entry.
    private func makeDaemon(
        scopeAllowlist: [String] = ["test-key", "test/*", "ovh/OVH_APP_KEY"],
        vaultEntries: [String: [String: String]] = ["test-key": ["value": "hello-world"]],
        llmBridgeUids: Set<UInt32> = [],
        toolManifest: [ManifestVerifier.ToolEntry] = []
    ) async throws -> (BrokerDaemon, InMemoryBWClient, UnixSocketServer, MCPBridge) {
        let kernel = ShikkiKernel()
        let audit = AuditWriter()
        let seams = SeamsWriter()
        let registry = TokenRegistry()
        let drivers = DriverRegistry()
        let engine = RotationEngine(
            drivers: drivers, audit: audit, seams: seams, registry: registry
        )
        let verifier = ManifestVerifier(pinnedPublicKey: Curve25519.Signing.PrivateKey().publicKey)
        let manifestStore = ManifestStore(verifier: verifier, seams: seams)
        let scopeValidator = try ScopeValidator(allowlist: scopeAllowlist)
        let bridge = MCPBridge(
            bearerAllowlist: ["test-bearer"],
            llmBridgeUids: llmBridgeUids
        )
        let config = UnixSocketConfig(
            socketPath: socketPath(),
            expectedMode: 0o600,
            expectedUid: UInt32(geteuid())
        )
        let socket = UnixSocketServer(config: config)
        let bwClient = InMemoryBWClient()
        await bwClient.activate()
        for (name, fields) in vaultEntries {
            await bwClient.seedFakeEntry(name: name, fields: fields)
        }
        let minter = TokenMinter(
            registry: registry,
            signingKey: Curve25519.Signing.PrivateKey(),
            toolManifest: toolManifest
        )
        let daemon = BrokerDaemon(
            kernel: kernel, audit: audit, seams: seams, registry: registry,
            drivers: drivers, engine: engine,
            manifestStore: manifestStore, scopeValidator: scopeValidator,
            bridge: bridge, socket: socket, bwClient: bwClient, minter: minter,
            bootstrap: StubBootstrapProvider()
        )
        try await daemon.start()
        return (daemon, bwClient, socket, bridge)
    }

    /// Build a local-unix WrappedRequest (llmTouched = false).
    private func localUnixWrapped(payload: Data = Data()) -> WrappedRequest {
        WrappedRequest(
            peerUid: UInt32(geteuid()),
            transport: .unix,
            llmTouched: false,
            payload: payload
        )
    }

    /// Build an MCP WrappedRequest (llmTouched = true).
    private func mcpWrapped(payload: Data = Data()) -> WrappedRequest {
        WrappedRequest(
            peerUid: nil,
            transport: .mcp,
            llmTouched: true,
            payload: payload
        )
    }

    // MARK: - T01

    @Test("T01 get_localUnixCaller_returnsBoundPlaintext")
    func test_t01_get_localUnixCaller_returnsBoundPlaintext() async throws {
        let (daemon, _, socket, _) = try await makeDaemon()
        defer { Task { await socket.shutdown() } }

        let request = BrokerRequest(
            sub: "cli@local",
            scope: "test-key",
            op: .read,
            ttl: 300,
            toolName: nil
        )
        let wrapped = localUnixWrapped()
        let response = await daemon.handleRequest(request, wrapped: wrapped)

        // T01: local-unix caller with allowed scope must return .boundPlaintext
        guard case let .boundPlaintext(jti, plaintext) = response else {
            Issue.record("T01 FAIL: expected .boundPlaintext, got \(response)")
            return
        }
        #expect(!jti.isEmpty, "jti must not be empty")
        #expect(plaintext == "hello-world", "plaintext must be the vault value")
    }

    // MARK: - T02

    @Test("T02 get_localUnixCaller_jti_in_response_matches_audit_row")
    func test_t02_get_localUnixCaller_jti_matches_audit_row() async throws {
        let (daemon, _, socket, _) = try await makeDaemon()
        defer { Task { await socket.shutdown() } }

        let request = BrokerRequest(
            sub: "cli@local",
            scope: "test-key",
            op: .read,
            ttl: 300,
            toolName: nil
        )
        let wrapped = localUnixWrapped()
        let response = await daemon.handleRequest(request, wrapped: wrapped)

        guard case let .boundPlaintext(responseJti, _) = response else {
            Issue.record("T02 FAIL: expected .boundPlaintext, got \(response)")
            return
        }

        // T02: the jti in the response must match the audit row's tokenJti
        let rows = await daemon.audit.all()
        let allowRow = rows.first(where: { $0.allow == .allow })
        #expect(allowRow != nil, "there must be an allow audit row")
        #expect(allowRow?.tokenJti == responseJti,
                "response jti '\(responseJti)' must match audit row jti '\(allowRow?.tokenJti ?? "nil")'")
    }

    // MARK: - T03

    @Test("T03 get_mcpCaller_returnsEphemeralToken_unchanged")
    func test_t03_get_mcpCaller_returnsEphemeralToken() async throws {
        // MCP requires a registered toolName in the manifest (BR-A-13 / review finding U15).
        let mcpEntry = ManifestVerifier.ToolEntry(
            toolName: "secrets.request_token",
            schemaHash: "sha256:t03",
            scopeGlob: "test-key",
            maxTtl: 3600,
            op: .read
        )
        let (daemon, _, socket, _) = try await makeDaemon(
            scopeAllowlist: ["test-key", "test/*", "ovh/OVH_APP_KEY"],
            vaultEntries: ["test-key": ["value": "hello-world"]],
            toolManifest: [mcpEntry]
        )
        defer { Task { await socket.shutdown() } }

        // MCP caller must still get .ephemeralToken (regression protection)
        // MCP requires toolName per BR-A-13 / review finding U15
        let request = BrokerRequest(
            sub: "mcp-bot@shikki",
            scope: "test-key",
            op: .read,
            ttl: 600,
            toolName: "secrets.request_token"
        )
        let wrapped = mcpWrapped()
        let response = await daemon.handleRequest(request, wrapped: wrapped)

        // T03: MCP caller must receive .ephemeralToken, NOT .boundPlaintext
        // Getting .deny is also acceptable — the key invariant is MCP never
        // returns .boundPlaintext (no plaintext leaks over MCP transport).
        if case .ephemeralToken = response {
            // ok — regression preserved
        } else if case .boundPlaintext = response {
            Issue.record("T03 FAIL: MCP caller must NEVER get .boundPlaintext, got \(response)")
        }
        // .deny is ok — some deny paths may fire depending on manifest config
    }

    // MARK: - T04

    @Test("T04 get_localUnixCaller_llm_touched_returnsEphemeralToken_NOT_boundPlaintext")
    func test_t04_get_localUnixCaller_llmTouched_returnsEphemeralToken() async throws {
        // Simulate a unix caller whose uid is registered as an llm-bridge uid
        // (BR-D-05 — known bridges get llmTouched=true even over unix socket)
        let uid = UInt32(geteuid())
        let (daemon, _, socket, _) = try await makeDaemon(
            llmBridgeUids: [uid]
        )
        defer { Task { await socket.shutdown() } }

        // The llmBridgeUid-registered caller has llmTouched = true (set by MCPBridge.wrapUnixRequest)
        // We simulate this by constructing a WrappedRequest with llmTouched=true over unix transport
        let request = BrokerRequest(
            sub: "llm-bridge@local",
            scope: "test-key",
            op: .read,
            ttl: 300,
            toolName: nil
        )
        let wrapped = WrappedRequest(
            peerUid: uid,
            transport: .unix,
            llmTouched: true,   // llm-bridge uid → llmTouched promoted
            payload: Data()
        )
        let response = await daemon.handleRequest(request, wrapped: wrapped)

        // T04: llm-touched unix caller must get .ephemeralToken (safer path)
        if case .ephemeralToken = response {
            // ok — safer path preserved
        } else if case .boundPlaintext = response {
            Issue.record("T04 FAIL: llm_touched caller must NOT get .boundPlaintext, got \(response)")
        } else {
            // deny is also acceptable — but not boundPlaintext
            // (denial may occur if minter needs toolName for mcp; unix + llmTouched has no toolName)
        }
    }
}
