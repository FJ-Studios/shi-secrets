import Crypto
import Foundation
@testable import ShiSecretsBrokerd
@testable import ShiSecretsKit
import Testing

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// 3rd-pass validator T1 — persist-failure + compensateRevoke seam
// emission (I2) integration test.
//
// Exercises the `handleRequest` path where `TokenMinter.persist` throws
// AFTER the audit allow row was already written. The 2nd-pass validator
// noted that this failure mode (disk full / connection drop in the v1.1
// DB swap) was implemented but never tested end-to-end.
//
// Expected behavior:
//   (a) audit row is present (pre-persist, BR-G-01 honored)
//   (b) compensateRevoke ran; because persist failed BEFORE any row
//       was inserted, `registry.revoke` throws `.invalidJti` — the
//       helper emits a `persistCompensationNoOp` seam instead of
//       silently swallowing the error
//   (c) handleRequest returns `.deny(.internalError)` (review finding
//       U3 — persist-catch-all is internalError, NOT incidentBypass).

@Suite("PersistFailure")
struct PersistFailureTests {

    private func socketPath() -> String {
        "/tmp/sh-pf-\(UUID().uuidString.prefix(8)).s"
    }

    @Test("persist failure → compensateRevoke + persistCompensationNoOp seam + audit allow row survived (T1)")
    func test_handleRequest_persistFailure_compensatesRevoke_auditRowStillPresent() async throws {
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
        let scopeValidator = try ScopeValidator(allowlist: ["ovh/OVH_APP_KEY"])
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

        // Inject the "disk full" fault — every insert throws
        // ShikkiSBT.Error.persistFailed-equivalent. The registry never
        // actually inserts the row, so compensateRevoke's subsequent
        // `registry.revoke` will throw `.invalidJti`.
        struct DiskFull: Swift.Error {}
        await registry.setTestInsertFaultInjector { _ in DiskFull() }

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

        // (c) response = .deny(.internalError)
        if case .deny(let reason) = response {
            #expect(reason == .internalError)
        } else {
            Issue.record("expected .deny(.internalError), got \(response)")
        }

        // (a) audit row present — the allow row was written BEFORE
        // persist was attempted (review finding U1). The subsequent
        // deny row is also written by writeDenyOrFailClosed.
        let rows = await audit.all()
        #expect(rows.count == 2)
        #expect(rows.first?.allow == .allow)
        #expect(rows.last?.allow == .deny)
        #expect(rows.last?.reason == .internalError)

        // (b) compensateRevoke ran → persistCompensationNoOp seam.
        let seamRows = await seams.all()
        let noOpSeams = seamRows.filter { row in
            if case .persistCompensationNoOp = row.signal { return true }
            return false
        }
        #expect(noOpSeams.count == 1)
        let seam = try #require(noOpSeams.first)
        #expect(seam.outcome == .bypassed)
        if case .persistCompensationNoOp(let scope) = seam.signal {
            #expect(scope == "ovh/OVH_APP_KEY")
        } else {
            Issue.record("expected persistCompensationNoOp, got \(seam.signal)")
        }
        // No token actually landed in the registry.
        let registryRows = await registry.all()
        #expect(registryRows.isEmpty)
    }
}
