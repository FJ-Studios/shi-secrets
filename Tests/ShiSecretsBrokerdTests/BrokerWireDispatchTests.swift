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

// BrokerWireDispatchTests — Phase 0.3c.
//
// Verifies the JSON-RPC method routing: secret.get arms the existing
// daemon.handleRequest path, and unknown methods fall through to
// WireResponse.methodNotFound.

@Suite("BrokerWireDispatch")
struct BrokerWireDispatchTests {

    private func socketPath() -> String {
        "/tmp/sh-disp-\(UUID().uuidString.prefix(8)).s"
    }

    private func makeDaemonAndBridge() async throws -> (BrokerDaemon, MCPBridge, UnixSocketServer) {
        let kernel = ShikkiKernel()
        let audit = AuditWriter()
        let seams = SeamsWriter()
        let registry = TokenRegistry()
        let drivers = DriverRegistry()
        let engine = RotationEngine(drivers: drivers, audit: audit, seams: seams, registry: registry)
        let verifier = ManifestVerifier(pinnedPublicKey: Curve25519.Signing.PrivateKey().publicKey)
        let manifestStore = ManifestStore(verifier: verifier, seams: seams)
        let scopeValidator = try ScopeValidator(allowlist: ["ovh/OVH_APP_KEY"])
        let bridge = MCPBridge(bearerAllowlist: ["bearer-1"])
        let config = UnixSocketConfig(
            socketPath: socketPath(),
            expectedMode: 0o600,
            expectedUid: UInt32(geteuid())
        )
        let socket = UnixSocketServer(config: config)
        let bwClient = InMemoryBWClient()
        await bwClient.activate()
        let minter = TokenMinter(
            registry: registry,
            signingKey: Curve25519.Signing.PrivateKey(),
            toolManifest: []
        )
        let daemon = BrokerDaemon(
            kernel: kernel, audit: audit, seams: seams, registry: registry,
            drivers: drivers, engine: engine,
            manifestStore: manifestStore, scopeValidator: scopeValidator,
            bridge: bridge, socket: socket, bwClient: bwClient, minter: minter,
            bootstrap: StubBootstrapProvider()
        )
        try await daemon.start()
        return (daemon, bridge, socket)
    }

    @Test("secret.get → ephemeralToken envelope via handleRequest path")
    func test_dispatch_secretGet_arrivesAtHandleRequest_returnsEphemeralToken() async throws {
        let (daemon, bridge, socket) = try await makeDaemonAndBridge()
        defer { Task { await socket.shutdown() } }
        let dispatcher = BrokerWireDispatcher(daemon: daemon, bridge: bridge)

        let params: JSONValue = .object([
            "sub": .string("claude@tusken"),
            "scope": .string("ovh/OVH_APP_KEY"),
            "op": .string("read"),
            "ttl": .int(600),
        ])
        let request = WireRequest(method: "secret.get", params: params, id: "req-1")

        let response = await dispatcher.dispatch(request, peerUid: UInt32(geteuid()))

        #expect(response.id == "req-1")
        #expect(response.error == nil)
        guard case .object(let obj) = response.result! else {
            Issue.record("result must be object, got \(String(describing: response.result))")
            return
        }
        #expect(obj["type"] == .string("ephemeralToken"))
    }

    @Test("Unknown method → WireResponse.methodNotFound (-32601)")
    func test_dispatch_unknownMethod_returnsMethodNotFound() async throws {
        let (daemon, bridge, socket) = try await makeDaemonAndBridge()
        defer { Task { await socket.shutdown() } }
        let dispatcher = BrokerWireDispatcher(daemon: daemon, bridge: bridge)

        let request = WireRequest(method: "secret.unknownVerb", params: nil, id: "req-2")
        let response = await dispatcher.dispatch(request, peerUid: UInt32(geteuid()))

        #expect(response.id == "req-2")
        #expect(response.result == nil)
        #expect(response.error?.code == WireErrorCode.methodNotFound)
    }

    @Test("secret.get with missing params → invalidParams (-32602)")
    func test_dispatch_secretGet_missingParams_returnsInvalidParams() async throws {
        let (daemon, bridge, socket) = try await makeDaemonAndBridge()
        defer { Task { await socket.shutdown() } }
        let dispatcher = BrokerWireDispatcher(daemon: daemon, bridge: bridge)

        let request = WireRequest(method: "secret.get", params: nil, id: "req-3")
        let response = await dispatcher.dispatch(request, peerUid: UInt32(geteuid()))

        #expect(response.error?.code == WireErrorCode.invalidParams)
    }

    @Test("secret.get with malformed op → invalidParams")
    func test_dispatch_secretGet_malformedOp_returnsInvalidParams() async throws {
        let (daemon, bridge, socket) = try await makeDaemonAndBridge()
        defer { Task { await socket.shutdown() } }
        let dispatcher = BrokerWireDispatcher(daemon: daemon, bridge: bridge)

        let params: JSONValue = .object([
            "sub": .string("c"),
            "scope": .string("ovh/OVH_APP_KEY"),
            "op": .string("not-a-real-op"),
            "ttl": .int(600),
        ])
        let request = WireRequest(method: "secret.get", params: params, id: "req-4")
        let response = await dispatcher.dispatch(request, peerUid: UInt32(geteuid()))

        #expect(response.error?.code == WireErrorCode.invalidParams)
    }
}
