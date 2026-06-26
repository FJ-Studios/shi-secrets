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

@Suite("KernelJobRegistration")
struct KernelJobRegistrationTests {

    private func socketPath() -> String {
        "/tmp/sh-k-\(UUID().uuidString.prefix(8)).s"
    }

    private func makeDaemon() async throws -> BrokerDaemon {
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
        let config = UnixSocketConfig(
            socketPath: socketPath(),
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
        return BrokerDaemon(
            kernel: kernel, audit: audit, seams: seams, registry: registry,
            drivers: drivers, engine: engine,
            manifestStore: manifestStore, gateway: gateway,
            bridge: bridge, socket: socket, bwClient: bwClient, minter: minter,
            bootstrap: StubBootstrapProvider()
        )
    }

    @Test("start registers exactly 6 kernel jobs")
    func test_brokerDaemon_start_registersExactly6KernelJobs() async throws {
        let daemon = try await makeDaemon()
        try await daemon.start()
        let registrations = await daemon.kernel.registrations()
        #expect(registrations.count == 6)
        await daemon.socket.shutdown()
    }

    @Test("kernel jobs have expected ids + QoS + schedules")
    func test_brokerDaemon_kernelJobs_haveExpectedIdsAndQosAndSchedules() async throws {
        let daemon = try await makeDaemon()
        try await daemon.start()

        let expected: [(id: String, qos: QoSTrack, schedule: Schedule)] = [
            ("secrets.rotation.hot",       .hot,      .interval(300)),
            ("secrets.rotation.warm",      .warm,     .interval(1_800)),
            ("secrets.rotation.cool",      .cool,     .interval(7_200)),
            ("secrets.rotation.external",  .external, .interval(21_600)),
            ("secrets.anomaly.listener",   .hot,      .onEvent("shikki.secrets.anomaly")),
            ("secrets.conversation.sweep", .warm,     .interval(900)),
        ]
        for (id, qos, schedule) in expected {
            guard let reg = await daemon.kernel.registration(id: id) else {
                Issue.record("missing job \(id)")
                continue
            }
            #expect(reg.qos == qos, "qos mismatch for \(id)")
            #expect(reg.schedule == schedule, "schedule mismatch for \(id)")
        }
        await daemon.socket.shutdown()
    }
}
