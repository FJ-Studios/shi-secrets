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

// BrokerWireDispatchBoundPlaintextTests — W4.2 TDD-first wire-dispatch tests.
//
// Tests T05-T07: verifies that BrokerWireDispatcher.dispatch("secret.get")
// emits result: .string(plaintext) for local-unix callers (not the object
// envelope that ProductionBrokerClient.get() cannot decode).
//
// T05: local-unix secret.get returns result: .string(plaintext)
// T06: encodes ephemeralToken envelope is UNCHANGED for MCP callers
//      (regression protection on existing wire shape)
// T07: round-trip — the .string(plaintext) result decoded by client is the
//      exact vault value

@Suite("BrokerWireDispatchBoundPlaintext")
struct BrokerWireDispatchBoundPlaintextTests {

    private func socketPath() -> String {
        "/tmp/sh-wdbp-\(UUID().uuidString.prefix(8)).s"
    }

    /// Build a dispatcher with a seeded vault entry.
    private func makeDispatcher(
        scopeAllowlist: [String] = ["test-key", "ovh/OVH_APP_KEY"],
        vaultEntry: (name: String, value: String) = ("test-key", "hello-world"),
        toolManifest: [ManifestVerifier.ToolEntry] = []
    ) async throws -> (BrokerWireDispatcher, UnixSocketServer, MCPBridge, InMemoryBWClient) {
        let kernel = ShikkiKernel()
        let audit = AuditWriter()
        let seams = SeamsWriter()
        let registry = TokenRegistry()
        let drivers = DriverRegistry()
        let engine = RotationEngine(drivers: drivers, audit: audit, seams: seams, registry: registry)
        let verifier = ManifestVerifier(pinnedPublicKey: Curve25519.Signing.PrivateKey().publicKey)
        let manifestStore = ManifestStore(verifier: verifier, seams: seams)
        let scopeValidator = try ScopeValidator(allowlist: scopeAllowlist)
        let bridge = MCPBridge(bearerAllowlist: ["mcp-bearer-t05"])
        let config = UnixSocketConfig(
            socketPath: socketPath(),
            expectedMode: 0o600,
            expectedUid: UInt32(geteuid())
        )
        let socket = UnixSocketServer(config: config)
        let bwClient = InMemoryBWClient()
        await bwClient.activate()
        await bwClient.seedFakeEntry(name: vaultEntry.name, fields: ["value": vaultEntry.value])
        let minter = TokenMinter(
            registry: registry,
            signingKey: Curve25519.Signing.PrivateKey(),
            toolManifest: toolManifest
        )
        let gateway = RequestGateway(
            scopeValidator: scopeValidator, bwClient: bwClient, audit: audit
        )
        let daemon = BrokerDaemon(
            kernel: kernel, audit: audit, seams: seams, registry: registry,
            drivers: drivers, engine: engine,
            manifestStore: manifestStore, gateway: gateway,
            bridge: bridge, socket: socket, bwClient: bwClient, minter: minter,
            bootstrap: StubBootstrapProvider()
        )
        try await daemon.start()
        let dispatcher = BrokerWireDispatcher(daemon: daemon, bridge: bridge)
        return (dispatcher, socket, bridge, bwClient)
    }

    // MARK: - T05

    @Test("T05 encodes_boundPlaintext_as_string — local-unix secret.get returns .string(plaintext)")
    func test_t05_localUnix_secretGet_returnsStringResult() async throws {
        let (dispatcher, socket, _, _) = try await makeDispatcher()
        defer { Task { await socket.shutdown() } }

        let req = WireRequest(
            method: "secret.get",
            params: .object(["name": .string("test-key")]),
            id: "t05"
        )
        let peerUid = UInt32(geteuid())
        let response = await dispatcher.dispatch(req, peerUid: peerUid)

        // T05: local-unix callers must get result: .string(plaintext), NOT an object
        #expect(response.error == nil, "no error expected for allowed scope")
        guard let result = response.result else {
            Issue.record("T05 FAIL: response.result is nil")
            return
        }
        guard case let .string(value) = result else {
            Issue.record("T05 FAIL: expected result to be .string, got \(result) — client wireDecodeFailed reproduced")
            return
        }
        #expect(value == "hello-world", "T05: plaintext must be the vault value")
    }

    // MARK: - T06

    @Test("T06 encodes_ephemeralToken_unchanged — MCP caller still gets object envelope")
    func test_t06_mcpCaller_secretGet_returnsEphemeralTokenObject() async throws {
        let mcpEntry = ManifestVerifier.ToolEntry(
            toolName: "secrets.request_token",
            schemaHash: "sha256:t06",
            scopeGlob: "test-key",
            maxTtl: 3600,
            op: .read
        )
        let (dispatcher, socket, _, _) = try await makeDispatcher(
            toolManifest: [mcpEntry]
        )
        defer { Task { await socket.shutdown() } }

        // MCP request uses canonical params with toolName
        let req = WireRequest(
            method: "secret.get",
            params: .object([
                "sub":      .string("mcp-bot@shikki"),
                "scope":    .string("test-key"),
                "op":       .string("read"),
                "ttl":      .int(600),
                "toolName": .string("secrets.request_token"),
            ]),
            id: "t06"
        )
        // MCP requests come with the bridge bearer validation pre-done;
        // but BrokerWireDispatcher.dispatch always uses wrapUnixRequest
        // (unix socket peerUid). For MCP transport test, we simulate
        // the MCP path by using a WrappedRequest with transport=.mcp
        // directly on the daemon, then verify the wire dispatch handles
        // the ephemeralToken correctly.
        //
        // Since BrokerWireDispatcher.dispatch always calls wrapUnixRequest,
        // we test the MCP regression by calling handleRequest directly with
        // an mcp-transport wrapped request and verifying the WireBridge
        // still encodes ephemeralToken as object.
        //
        // Indirect approach: build a BrokerResponse.ephemeralToken and
        // verify toWireResponse() still produces the object envelope.
        let fakeClaims = ShikkiSBT.Claims(
            sub: "bot:shi-mcp",
            scope: "test-key",
            op: .read,
            ttl: 600,
            jti: "01JABCDEFGHJKMNPQRSTVWXYZ1",
            nbf: Date(timeIntervalSince1970: 1_700_000_000),
            diesAt: Date(timeIntervalSince1970: 1_700_000_600),
            llmTouched: true
        )
        let resp = BrokerResponse.ephemeralToken(ShikkiSBT(claims: fakeClaims))
        let wireResp = try resp.toWireResponse(id: "t06")

        // T06 regression: ephemeralToken encoding unchanged — result is object
        guard case .object(let obj) = wireResp.result else {
            Issue.record("T06 FAIL: ephemeralToken must encode as object, got \(String(describing: wireResp.result))")
            return
        }
        #expect(obj["type"] == .string("ephemeralToken"))
        #expect(obj["claims"] != nil)
    }

    // MARK: - T07

    @Test("T07 decodes_boundPlaintext_round_trip — .string result decoded by client succeeds")
    func test_t07_roundTrip_stringResult_decodedByClient() async throws {
        // Simulate what ProductionBrokerClient.get() does:
        // 1. Gets result from dispatcher
        // 2. Checks: guard case let .string(value) = result
        // This test ensures the chosen wire shape is decoded correctly.

        let (dispatcher, socket, _, _) = try await makeDispatcher()
        defer { Task { await socket.shutdown() } }

        let req = WireRequest(
            method: "secret.get",
            params: .object(["name": .string("test-key")]),
            id: "t07"
        )
        let response = await dispatcher.dispatch(req, peerUid: UInt32(geteuid()))

        guard let result = response.result else {
            Issue.record("T07 FAIL: response.result is nil")
            return
        }

        // Simulate ProductionBrokerClient.get() decode path
        var decoded: String? = nil
        if case let .string(value) = result {
            decoded = value
        }

        #expect(decoded != nil, "T07: ProductionBrokerClient.get() decode path must succeed — got \(result)")
        #expect(decoded == "hello-world", "T07: decoded value must match vault entry")
    }
}
