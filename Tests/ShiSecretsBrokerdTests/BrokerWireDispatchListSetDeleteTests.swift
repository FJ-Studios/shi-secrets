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

// BrokerWireDispatchListSetDeleteTests — coverage for secret.list / secret.set
// / secret.delete dispatch paths (W3 phase).
//
// Gaps addressed:
//   TCP-LD-01  secret.list returns .array of VaultEntryRef objects — wire shape correct
//   TCP-LD-02  secret.list on empty vault returns empty array
//   TCP-LD-03  secret.set + secret.list round-trip — set entry appears in list
//   TCP-LD-04  secret.delete idempotent (delete missing name does not error)
//   TCP-LD-05  secret.set + secret.delete — list no longer contains deleted name
//   TCP-LD-06  secret.list filter glob — prefix match only
//
// Bug 2 fix (v0.1.0): secret.list now returns [VaultEntryRef] objects (not bare
// [String] names). Assertions updated to extract the `name` field from the object.
//
// All tests use InMemoryBWClient with no real Vaultwarden connection.

@Suite("BrokerWireDispatch — list/set/delete")
struct BrokerWireDispatchListSetDeleteTests {

    // MARK: - Helper: extract entry names from [VaultEntryRef] wire response
    //
    // Bug 2 fix: secret.list now returns VaultEntryRef objects, not bare strings.
    // Each item is a JSONValue.object with a "name" field.
    private func entryNames(from items: [JSONValue]) -> [String] {
        items.compactMap { item -> String? in
            guard case .object(let obj) = item,
                  case .string(let n) = obj["name"] else { return nil }
            return n
        }
    }

    private func socketPath() -> String {
        "/tmp/sh-lsd-\(UUID().uuidString.prefix(8)).s"
    }

    /// Returns daemon + bridge + bwClient so tests can seed/inspect entries.
    private func makeDaemonBridgeAndClient() async throws -> (
        dispatcher: BrokerWireDispatcher,
        bwClient: InMemoryBWClient,
        socket: UnixSocketServer
    ) {
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
        let dispatcher = BrokerWireDispatcher(daemon: daemon, bridge: bridge)
        return (dispatcher, bwClient, socket)
    }

    // MARK: - secret.list

    @Test("TCP-LD-01: secret.list — result is array of VaultEntryRef objects (bug 2 fix)")
    func test_secretList_resultIsArray() async throws {
        let (dispatcher, bwClient, socket) = try await makeDaemonBridgeAndClient()
        defer { Task { await socket.shutdown() } }

        // Seed one entry so we can verify the shape of a non-empty result.
        try await bwClient.set(name: "shape-test", value: "v")

        let request = WireRequest(method: "secret.list", params: nil, id: "ld-01")
        let response = await dispatcher.dispatch(request, peerUid: UInt32(geteuid()))

        #expect(response.id == "ld-01")
        #expect(response.error == nil, "secret.list must not error; got \(String(describing: response.error))")
        guard case .array(let items) = response.result! else {
            Issue.record("result must be array; got \(String(describing: response.result))")
            return
        }
        // Bug 2 fix: each item must be a VaultEntryRef object, not a bare string.
        guard let first = items.first else {
            Issue.record("expected at least one item in the seeded vault")
            return
        }
        guard case .object(let obj) = first else {
            Issue.record("Bug 2: list items must be VaultEntryRef objects, got \(first)")
            return
        }
        // VaultEntryRef must carry at minimum: name, scope, tier, usage_state,
        // last_rotated, rotation_due.
        #expect(obj["name"] != nil, "VaultEntryRef must have 'name' field")
        #expect(obj["scope"] != nil, "VaultEntryRef must have 'scope' field")
        #expect(obj["tier"] != nil, "VaultEntryRef must have 'tier' field")
    }

    @Test("TCP-LD-02: secret.list on empty vault returns empty array")
    func test_secretList_emptyVault_returnsEmptyArray() async throws {
        let (dispatcher, _, socket) = try await makeDaemonBridgeAndClient()
        defer { Task { await socket.shutdown() } }

        let request = WireRequest(method: "secret.list", params: nil, id: "ld-02")
        let response = await dispatcher.dispatch(request, peerUid: UInt32(geteuid()))

        guard case .array(let items) = response.result! else {
            Issue.record("result must be array")
            return
        }
        #expect(items.isEmpty, "empty vault must return [] but got \(items.count) items")
    }

    @Test("TCP-LD-03: secret.set + secret.list round-trip — set entry appears in list result")
    func test_secretSetThenList_entryAppearsInList() async throws {
        let (dispatcher, _, socket) = try await makeDaemonBridgeAndClient()
        defer { Task { await socket.shutdown() } }

        // Set a secret
        let setParams: JSONValue = .object([
            "name": .string("ci-github-token"),
            "value": .string("ghp_test12345"),
        ])
        let setReq = WireRequest(method: "secret.set", params: setParams, id: "ld-03-set")
        let setResp = await dispatcher.dispatch(setReq, peerUid: UInt32(geteuid()))
        #expect(setResp.error == nil, "secret.set must not error; got \(String(describing: setResp.error))")

        // Now list — entry must be present
        let listReq = WireRequest(method: "secret.list", params: nil, id: "ld-03-list")
        let listResp = await dispatcher.dispatch(listReq, peerUid: UInt32(geteuid()))
        #expect(listResp.error == nil)
        guard case .array(let items) = listResp.result! else {
            Issue.record("list result must be array")
            return
        }
        // Bug 2 fix: items are VaultEntryRef objects — extract names to check.
        let names = entryNames(from: items)
        #expect(
            names.contains("ci-github-token"),
            "list must contain 'ci-github-token' after set; got names=\(names)"
        )
    }

    @Test("TCP-LD-04: secret.delete idempotent — deleting non-existent name succeeds")
    func test_secretDelete_nonExistentName_noError() async throws {
        let (dispatcher, _, socket) = try await makeDaemonBridgeAndClient()
        defer { Task { await socket.shutdown() } }

        let deleteParams: JSONValue = .object(["name": .string("never-set-key")])
        let req = WireRequest(method: "secret.delete", params: deleteParams, id: "ld-04")
        let response = await dispatcher.dispatch(req, peerUid: UInt32(geteuid()))

        #expect(response.error == nil, "delete of non-existent key must not error; got \(String(describing: response.error))")
    }

    @Test("TCP-LD-05: secret.set + secret.delete — list no longer contains deleted name")
    func test_secretSetDeleteThenList_entryAbsent() async throws {
        let (dispatcher, _, socket) = try await makeDaemonBridgeAndClient()
        defer { Task { await socket.shutdown() } }

        // Set
        let setParams: JSONValue = .object(["name": .string("ovh-dns-key"), "value": .string("secret-val")])
        let setResp = await dispatcher.dispatch(
            WireRequest(method: "secret.set", params: setParams, id: "ld-05-set"),
            peerUid: UInt32(geteuid())
        )
        #expect(setResp.error == nil)

        // Delete
        let delParams: JSONValue = .object(["name": .string("ovh-dns-key")])
        let delResp = await dispatcher.dispatch(
            WireRequest(method: "secret.delete", params: delParams, id: "ld-05-del"),
            peerUid: UInt32(geteuid())
        )
        #expect(delResp.error == nil)

        // List — must be empty / not contain deleted name
        let listResp = await dispatcher.dispatch(
            WireRequest(method: "secret.list", params: nil, id: "ld-05-list"),
            peerUid: UInt32(geteuid())
        )
        guard case .array(let items) = listResp.result! else {
            Issue.record("list result must be array")
            return
        }
        // Bug 2 fix: items are VaultEntryRef objects — extract names to check.
        let names = entryNames(from: items)
        #expect(
            !names.contains("ovh-dns-key"),
            "deleted key must not appear in list; got names=\(names)"
        )
    }

    @Test("TCP-LD-06: secret.list with prefix filter — only matching entries returned")
    func test_secretList_filterGlob_prefixMatchOnly() async throws {
        let (dispatcher, _, socket) = try await makeDaemonBridgeAndClient()
        defer { Task { await socket.shutdown() } }

        // Seed three entries with different prefixes
        for (name, value) in [("ci-gh-token", "v1"), ("ci-gh-app-key", "v2"), ("ovh-dns-key", "v3")] {
            let setParams: JSONValue = .object(["name": .string(name), "value": .string(value)])
            _ = await dispatcher.dispatch(
                WireRequest(method: "secret.set", params: setParams, id: "seed-\(name)"),
                peerUid: UInt32(geteuid())
            )
        }

        // List with filter "ci-*"
        let filterParams: JSONValue = .object(["filter": .string("ci-*")])
        let listResp = await dispatcher.dispatch(
            WireRequest(method: "secret.list", params: filterParams, id: "ld-06"),
            peerUid: UInt32(geteuid())
        )
        #expect(listResp.error == nil)
        guard case .array(let items) = listResp.result! else {
            Issue.record("list result must be array")
            return
        }
        // Bug 2 fix: items are VaultEntryRef objects — extract names to check.
        let names = entryNames(from: items)
        #expect(
            names.contains("ci-gh-token") && names.contains("ci-gh-app-key"),
            "ci-* filter must return ci- prefixed entries; got names=\(names)"
        )
        #expect(
            !names.contains("ovh-dns-key"),
            "ci-* filter must NOT return ovh- entries; got names=\(names)"
        )
    }
}
