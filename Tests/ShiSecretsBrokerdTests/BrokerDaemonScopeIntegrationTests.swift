import Crypto
import Foundation
import Testing
@testable import ShiSecretsBrokerd
import ShiSecretsKit

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// BrokerDaemon scope integration tests (T11-T14).
//
// W4.1 of spec e8c4a921-7d3b-4f5e-9a2c-1d6b8f4e3a91
// RED-FIRST: these tests were written before BrokerdSettings was wired.
// They close the W5 smoke: secret.get fails with scopePatternDenied when
// the allowlist is empty (the bug), but should succeed when properly configured.

@Suite("BrokerDaemon Scope Integration")
struct BrokerDaemonScopeIntegrationTests {

    private func socketPath() -> String {
        "/tmp/sh-scope-\(UUID().uuidString.prefix(8)).s"
    }

    private func makeDaemon(
        scopeAllowlist: [String]
    ) async throws -> (BrokerDaemon, InMemoryBWClient, UnixSocketServer) {
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
        let bridge = MCPBridge(bearerAllowlist: ["bearer-1"])
        let config = UnixSocketConfig(
            socketPath: socketPath(),
            expectedMode: 0o600,
            expectedUid: UInt32(geteuid())
        )
        let socket = UnixSocketServer(config: config)
        let bwClient = InMemoryBWClient()
        await bwClient.activate()
        let signingKey = Curve25519.Signing.PrivateKey()
        let minter = TokenMinter(
            registry: registry, signingKey: signingKey, toolManifest: []
        )
        let daemon = BrokerDaemon(
            kernel: kernel, audit: audit, seams: seams, registry: registry,
            drivers: drivers, engine: engine,
            manifestStore: manifestStore, scopeValidator: scopeValidator,
            bridge: bridge, socket: socket, bwClient: bwClient, minter: minter,
            bootstrap: StubBootstrapProvider()
        )
        return (daemon, bwClient, socket)
    }

    private func makeWrapped() -> WrappedRequest {
        WrappedRequest(
            peerUid: UInt32(geteuid()),
            transport: .unix,
            llmTouched: false,
            payload: Data()
        )
    }

    // MARK: - T11: secretGet_returnsValueWhenScopeMatches

    @Test("T11 secretGet_returnsValueWhenScopeMatches — scope match is not denied")
    func secretGet_returnsValueWhenScopeMatches() async throws {
        // allowlist must contain the exact scope (or ** for wildcard)
        // ScopeValidator.validate uses allowlist.contains — exact match needed.
        let (daemon, bwClient, socket) = try await makeDaemon(
            scopeAllowlist: ["test/integration"]
        )
        try await daemon.start()
        defer { Task { await socket.shutdown() } }

        // Seed the entry
        await bwClient.seedFakeEntry(name: "test/integration", fields: ["value": "secret-value"])

        let request = BrokerRequest(
            sub: "user.test",
            scope: "test/integration",
            op: .read,
            ttl: 300,
            toolName: nil
        )
        let wrapped = makeWrapped()
        let response = await daemon.handleRequest(request, wrapped: wrapped)

        // Should NOT be a scope-pattern-denied response
        if case .deny(let reason) = response {
            #expect(reason != .scopePatternDenied,
                    "Matching scope should not return scopePatternDenied, got deny(\(reason))")
        }
        // ephemeralToken (success) or other non-scope deny is acceptable
    }

    // MARK: - T12: secretGet_returnsScopePatternDeniedWhenNoMatch

    @Test("T12 secretGet_returnsScopePatternDeniedWhenNoMatch — non-matching scope is denied")
    func secretGet_returnsScopePatternDeniedWhenNoMatch() async throws {
        // allowlist only allows "test/integration" — "prod/secret" should be denied
        let (daemon, bwClient, socket) = try await makeDaemon(
            scopeAllowlist: ["test/integration"]
        )
        try await daemon.start()
        defer { Task { await socket.shutdown() } }

        await bwClient.seedFakeEntry(name: "prod/secret", fields: ["value": "secret-value"])

        let request = BrokerRequest(
            sub: "user.test",
            scope: "prod/secret",
            op: .read,
            ttl: 300,
            toolName: nil
        )
        let wrapped = makeWrapped()
        let response = await daemon.handleRequest(request, wrapped: wrapped)

        if case .deny(let reason) = response {
            #expect(reason == .scopePatternDenied,
                    "Non-matching scope should return scopePatternDenied")
        } else {
            Issue.record("Expected .deny(.scopePatternDenied) but got \(response)")
        }
    }

    // MARK: - T13: secretSet_alwaysSucceedsRegardlessOfScopeAllowlist

    @Test("T13 secretSet_alwaysSucceedsRegardlessOfScopeAllowlist — set bypasses scope validation")
    func secretSet_alwaysSucceedsRegardlessOfScopeAllowlist() async throws {
        // With empty allowlist (deny-all for get), set should still work.
        let (daemon, _, socket) = try await makeDaemon(scopeAllowlist: [])
        try await daemon.start()
        defer { Task { await socket.shutdown() } }

        // secret.set goes through BrokerWireDispatcher directly, NOT handleRequest.
        // Verify by dispatching a set request and checking it's not scope-denied.
        let dispatcher = BrokerWireDispatcher(daemon: daemon, bridge: MCPBridge(bearerAllowlist: []))
        let wireReq = WireRequest(
            method: "secret.set",
            params: .object(["name": .string("prod/secret"), "value": .string("my-val")]),
            id: "set-1"
        )
        let peerUid = UInt32(geteuid())
        let wireResp = await dispatcher.dispatch(wireReq, peerUid: peerUid)

        // Even with empty allowlist, set should not return scope_pattern_denied
        if let errorObj = wireResp.error {
            #expect(!errorObj.message.contains("scope_pattern_denied"),
                    "secret.set should NOT be gated by scope validator; got error: \(errorObj.message)")
        }
        // null error means success
    }

    // MARK: - T14: secretList_alwaysSucceedsRegardlessOfScopeAllowlist

    @Test("T14 secretList_alwaysSucceedsRegardlessOfScopeAllowlist — list bypasses scope validation")
    func secretList_alwaysSucceedsRegardlessOfScopeAllowlist() async throws {
        // With empty allowlist (deny-all for get), list should still work.
        let (daemon, _, socket) = try await makeDaemon(scopeAllowlist: [])
        try await daemon.start()
        defer { Task { await socket.shutdown() } }

        let dispatcher = BrokerWireDispatcher(daemon: daemon, bridge: MCPBridge(bearerAllowlist: []))
        let wireReq = WireRequest(
            method: "secret.list",
            params: .object([:]),
            id: "list-1"
        )
        let peerUid = UInt32(geteuid())
        let wireResp = await dispatcher.dispatch(wireReq, peerUid: peerUid)

        // Even with empty allowlist, list should not return scope_pattern_denied
        if let errorObj = wireResp.error {
            #expect(!errorObj.message.contains("scope_pattern_denied"),
                    "secret.list should NOT be gated by scope validator; got error: \(errorObj.message)")
        }
    }
}
