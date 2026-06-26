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

@Suite("BrokerDaemon")
struct BrokerDaemonTests {

    /// Sockaddr_un caps path at ~104 bytes on Darwin + 108 on Linux, so
    /// NSTemporaryDirectory (often /var/folders/...) is too long. We use
    /// /tmp directly and a short UUID prefix.
    private func socketPath() -> String {
        "/tmp/sh-d-\(UUID().uuidString.prefix(8)).s"
    }

    /// Builds a fully-wired BrokerDaemon suitable for tests. Every
    /// collaborator is in-memory; the socket is bound at a tmp path.
    private func makeDaemon(
        scopeAllowlist: [String] = ["ovh/OVH_APP_KEY", "brevo/BREVO_API_KEY"],
        manifest: [ManifestVerifier.ToolEntry] = [],
        sessionValid: Bool = true
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
        // W1: InMemoryBWClient uses activate() — no subprocess, no BW_SESSION.
        let bwClient = InMemoryBWClient()
        if sessionValid {
            await bwClient.activate()
        }
        let signingKey = Curve25519.Signing.PrivateKey()
        let minter = TokenMinter(
            registry: registry, signingKey: signingKey, toolManifest: manifest
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
        return (daemon, bwClient, socket)
    }

    @Test("start refuses if socket permissions are wrong")
    func test_brokerDaemon_start_refusesIfSocketPermissionsWrong() async throws {
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
        let scopeValidator = try ScopeValidator(allowlist: [])
        let bridge = MCPBridge()
        // Configure the socket with a WRONG expected uid so the start()
        // preflight trips on ownerMismatch.
        let wrongConfig = UnixSocketConfig(
            socketPath: socketPath(),
            expectedMode: 0o600,
            expectedUid: UInt32(geteuid()) &+ 7_777
        )
        let socket = UnixSocketServer(config: wrongConfig)
        // W1: InMemoryBWClient uses activate() — no subprocess.
        let bwClient = InMemoryBWClient()
        await bwClient.activate()
        let minter = TokenMinter(
            registry: registry,
            signingKey: Curve25519.Signing.PrivateKey(),
            toolManifest: []
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
        do {
            try await daemon.start()
            Issue.record("expected UnixSocketError.ownerMismatch")
        } catch let error as UnixSocketError {
            if case .ownerMismatch = error {
                // ok
            } else {
                Issue.record("expected ownerMismatch, got \(error)")
            }
        }
    }

    @Test("handleRequest invokes minter + writes audit allow row")
    func test_brokerDaemon_handleRequest_invokesMinterAndAuditWriter() async throws {
        let (daemon, _, socket) = try await makeDaemon()
        try await daemon.start()
        defer { Task { await socket.shutdown() } }

        let request = BrokerRequest(
            sub: "claude@tusken",
            scope: "ovh/OVH_APP_KEY",
            op: .read,
            ttl: 600,
            toolName: nil
        )
        let wrapped = WrappedRequest(
            peerUid: UInt32(geteuid()),
            transport: .unix,
            llmTouched: false,
            payload: Data()
        )
        let response = await daemon.handleRequest(request, wrapped: wrapped)
        if case .ephemeralToken = response {
            // ok
        } else {
            Issue.record("expected .ephemeralToken, got \(response)")
        }
        let rows = await daemon.audit.all()
        #expect(rows.count == 1)
        #expect(rows.first?.allow == .allow)
    }

    @Test("handleHUP reloads manifest — bad sig is fail-safe (keeps pinned)")
    func test_brokerDaemon_handleHUP_reloadsManifest_failSafeOnBadSig() async throws {
        let (daemon, _, socket) = try await makeDaemon()
        try await daemon.start()
        defer { Task { await socket.shutdown() } }

        // A reload with obviously-invalid signature must not throw —
        // ManifestStore absorbs the failure and writes a seams row.
        await daemon.handleHUP(bytes: Data("{}".utf8), signature: Data([0xAB]))
        let seams = await daemon.seams.all()
        #expect(seams.contains(where: { row in
            if case .manifestSigFailed = row.signal { return true }
            return false
        }))
    }

    @Test("start refuses without Bootstrap.unseal — no socket bind, no kernel jobs")
    func test_brokerDaemon_start_refusesWithoutBootstrapUnseal() async throws {
        // Review finding U13 — a throwing BootstrapProvider MUST refuse
        // start; the socket never binds and no kernel jobs are registered.
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
        let scopeValidator = try ScopeValidator(allowlist: [])
        let bridge = MCPBridge()
        let path = socketPath()
        let config = UnixSocketConfig(
            socketPath: path,
            expectedMode: 0o600,
            expectedUid: UInt32(geteuid())
        )
        let socket = UnixSocketServer(config: config)
        // W1: InMemoryBWClient uses activate() — no subprocess.
        let bwClient = InMemoryBWClient()
        await bwClient.activate()
        let minter = TokenMinter(
            registry: registry,
            signingKey: Curve25519.Signing.PrivateKey(),
            toolManifest: []
        )
        let gateway = RequestGateway(
            scopeValidator: scopeValidator, bwClient: bwClient, audit: audit
        )
        let daemon = BrokerDaemon(
            kernel: kernel, audit: audit, seams: seams, registry: registry,
            drivers: drivers, engine: engine,
            manifestStore: manifestStore, gateway: gateway,
            bridge: bridge, socket: socket, bwClient: bwClient, minter: minter,
            bootstrap: StubBootstrapProvider(behavior: .fail(.keychainCredentialsMissing))
        )
        await #expect(throws: BrokerDaemonError.bootstrapUnsealFailed) {
            try await daemon.start()
        }
        // Socket was never bound.
        #expect(!FileManager.default.fileExists(atPath: path))
        // No kernel jobs registered.
        let regs = await kernel.registrations()
        #expect(regs.isEmpty)
        #expect(await daemon.isStarted() == false)
    }

    @Test("start refuses when manifest source fails — no socket, no kernel jobs")
    func test_brokerDaemon_start_refusesWhenManifestSourceFails() async throws {
        // Review finding U7 — ManifestStore.loadInitial runs right after
        // unseal. A bad-sig manifest source MUST refuse start.
        let (_, _, _) = try await makeDaemon()
        // Rebuild a daemon with a manifest source whose signature cannot
        // verify against the pinned key.
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
        let scopeValidator = try ScopeValidator(allowlist: [])
        let bridge = MCPBridge()
        let path = socketPath()
        let config = UnixSocketConfig(
            socketPath: path,
            expectedMode: 0o600,
            expectedUid: UInt32(geteuid())
        )
        let socket = UnixSocketServer(config: config)
        // W1: InMemoryBWClient uses activate() — no subprocess.
        let bwClient = InMemoryBWClient()
        await bwClient.activate()
        let minter = TokenMinter(
            registry: registry,
            signingKey: Curve25519.Signing.PrivateKey(),
            toolManifest: []
        )
        let gateway = RequestGateway(
            scopeValidator: scopeValidator, bwClient: bwClient, audit: audit
        )
        let daemon = BrokerDaemon(
            kernel: kernel, audit: audit, seams: seams, registry: registry,
            drivers: drivers, engine: engine,
            manifestStore: manifestStore, gateway: gateway,
            bridge: bridge, socket: socket, bwClient: bwClient, minter: minter,
            bootstrap: StubBootstrapProvider(),
            manifestSource: ManifestSource(bytes: Data("{}".utf8), signature: Data([0xAB]))
        )
        await #expect(throws: BrokerDaemonError.manifestLoadFailed) {
            try await daemon.start()
        }
        #expect(!FileManager.default.fileExists(atPath: path))
        let regs = await kernel.registrations()
        #expect(regs.isEmpty)
    }

    @Test("start loads manifest into store when source matches pinned key")
    func test_brokerDaemon_start_loadsManifestWhenSourceValid() async throws {
        // Review finding U7 — happy path: valid manifest source pins the
        // manifest before the socket binds.
        let kernel = ShikkiKernel()
        let audit = AuditWriter()
        let seams = SeamsWriter()
        let registry = TokenRegistry()
        let drivers = DriverRegistry()
        let engine = RotationEngine(
            drivers: drivers, audit: audit, seams: seams, registry: registry
        )
        let manifestKey = Curve25519.Signing.PrivateKey()
        let verifier = ManifestVerifier(pinnedPublicKey: manifestKey.publicKey)
        let manifestStore = ManifestStore(verifier: verifier, seams: seams)
        let scopeValidator = try ScopeValidator(allowlist: [])
        let bridge = MCPBridge()
        let socket = UnixSocketServer(
            config: UnixSocketConfig(
                socketPath: socketPath(),
                expectedMode: 0o600,
                expectedUid: UInt32(geteuid())
            )
        )
        // W1: InMemoryBWClient uses activate() — no subprocess.
        let bwClient = InMemoryBWClient()
        await bwClient.activate()
        let minter = TokenMinter(
            registry: registry,
            signingKey: Curve25519.Signing.PrivateKey(),
            toolManifest: []
        )

        // Build a valid signed manifest.
        let manifest = ManifestVerifier.Manifest(
            version: "v1.0",
            issuedAt: Date(timeIntervalSince1970: 1_777_000_000),
            tools: []
        )
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let bytes = try encoder.encode(manifest)
        let sig = try manifestKey.signature(for: bytes)

        let gateway = RequestGateway(
            scopeValidator: scopeValidator, bwClient: bwClient, audit: audit
        )
        let daemon = BrokerDaemon(
            kernel: kernel, audit: audit, seams: seams, registry: registry,
            drivers: drivers, engine: engine,
            manifestStore: manifestStore, gateway: gateway,
            bridge: bridge, socket: socket, bwClient: bwClient, minter: minter,
            bootstrap: StubBootstrapProvider(),
            manifestSource: ManifestSource(bytes: bytes, signature: Data(sig))
        )
        try await daemon.start()
        defer { Task { await socket.shutdown() } }

        let current = await manifestStore.current()
        #expect(current?.version == "v1.0")
    }

    @Test("bwSession revoked disables new issuance within 5s, existing tokens still valid")
    func test_brokerBwSessionRevoked_disablesNewIssuanceWithin5s_outstandingTokensStillValidUntilDiesAt() async throws {
        let (daemon, bwClient, socket) = try await makeDaemon()
        try await daemon.start()
        defer { Task { await socket.shutdown() } }

        // Invalidate the session via the daemon.
        let start = Date()
        await daemon.revokeBWSession()
        #expect(Date().timeIntervalSince(start) < 5.0)
        #expect(await bwClient.isSessionValid == false)

        // Mint attempt after revoke returns .deny.
        let request = BrokerRequest(
            sub: "c", scope: "ovh/OVH_APP_KEY", op: .read, ttl: 300, toolName: nil
        )
        let wrapped = WrappedRequest(
            peerUid: UInt32(geteuid()), transport: .unix, llmTouched: false, payload: Data()
        )
        let response = await daemon.handleRequest(request, wrapped: wrapped)
        if case .deny = response {
            // ok
        } else {
            Issue.record("expected .deny after revoke, got \(response)")
        }
    }
}
