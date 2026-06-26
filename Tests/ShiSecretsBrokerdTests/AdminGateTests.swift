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

// AdminGate tests (item #9 — BR-F-08 / BR-F-09 / BR-F-10 / BR-F-11).
//
// Drive `BrokerDaemon.revokeAllBots(signedBy:)` with:
//   1. An unsigned / tampered envelope — asserts refusal.
//   2. A valid signed envelope — asserts revoke runs AND the seam
//      carries the actor field.
//   3. A signature produced under the MCP manifest domain — asserts
//      domain separation refuses it even though the key is identical.

@Suite("AdminGate")
struct AdminGateTests {

    private func socketPath() -> String {
        "/tmp/sh-ad-\(UUID().uuidString.prefix(8)).s"
    }

    /// Build a daemon whose admin verifier pins the given public key.
    /// Seeds a couple of non-passkey rows into the registry so
    /// `revokeAllBots` has something to do.
    private func makeDaemon(
        adminPublicKey: Curve25519.Signing.PublicKey,
        clock: @escaping @Sendable () -> Date = { Date() }
    ) async throws -> (
        daemon: BrokerDaemon,
        socket: UnixSocketServer,
        seams: SeamsWriter,
        registry: TokenRegistry
    ) {
        let kernel = ShikkiKernel()
        let audit = AuditWriter()
        let seams = SeamsWriter()
        let registry = TokenRegistry()
        let drivers = DriverRegistry()
        let engine = RotationEngine(
            drivers: drivers, audit: audit, seams: seams, registry: registry
        )
        let verifier = ManifestVerifier(
            pinnedPublicKey: Curve25519.Signing.PrivateKey().publicKey
        )
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
        let adminVerifier = AdminActionVerifier(
            pinnedPublicKey: adminPublicKey,
            clock: clock
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
            adminVerifier: adminVerifier
        )
        // Seed two non-passkey rows so revokeAllBots returns > 0.
        let now = Date()
        try await registry.insert(
            TokenRegistry.Row(
                jti: "01JABCDEFGHJKMNPQRSTVWXYA1",
                sub: "bot:ovh",
                scope: "ovh/*",
                op: .read,
                nbf: now,
                diesAt: now.addingTimeInterval(600),
                llmTouched: false,
                passkeyPath: false
            )
        )
        try await registry.insert(
            TokenRegistry.Row(
                jti: "01JABCDEFGHJKMNPQRSTVWXYA2",
                sub: "bot:brevo",
                scope: "brevo/*",
                op: .read,
                nbf: now,
                diesAt: now.addingTimeInterval(600),
                llmTouched: false,
                passkeyPath: false
            )
        )
        return (daemon, socket, seams, registry)
    }

    /// ULIDs of the two seeded rows (exposed so tests can assert on them).
    private let seededJtiA = "01JABCDEFGHJKMNPQRSTVWXYA1"
    private let seededJtiB = "01JABCDEFGHJKMNPQRSTVWXYA2"

    @Test("revokeAllBots rejects an envelope with an invalid signature")
    func test_brokerDaemon_revokeAllBots_unsignedRejected() async throws {
        let adminKey = Curve25519.Signing.PrivateKey()
        let (daemon, socket, _, registry) = try await makeDaemon(
            adminPublicKey: adminKey.publicKey
        )
        defer { Task { await socket.shutdown() } }

        // Build a valid envelope but tamper the signature — the daemon
        // MUST refuse with `adminSignatureInvalid`.
        let envelope = AdminAction(
            domain: AdminActionVerifier.expectedDomain,
            action: .revokeAllBots,
            nonce: "NNNNNNNNNNNNNNNNNNNNN1",
            issuedAt: Date(),
            actor: "Fr0zenSide@obyw.one"
        )
        let bytes = try envelope.canonicalBytes()
        var sig = Data(try adminKey.signature(for: bytes))
        sig[0] ^= 0xFF // tamper
        let signed = SignedAdminAction(envelope: envelope, signature: sig)

        await #expect(throws: BrokerDaemonError.adminSignatureInvalid) {
            _ = try await daemon.revokeAllBots(signedBy: signed)
        }
        // The registry MUST be untouched on refusal.
        #expect(await registry.isRevoked(jti: seededJtiA) == false)
        #expect(await registry.isRevoked(jti: seededJtiB) == false)
    }

    @Test("revokeAllBots with a valid signed envelope revokes and writes a seam carrying the actor")
    func test_brokerDaemon_revokeAllBots_validSigned_revokesAndWritesSeamWithActor() async throws {
        let adminKey = Curve25519.Signing.PrivateKey()
        let (daemon, socket, seams, registry) = try await makeDaemon(
            adminPublicKey: adminKey.publicKey
        )
        defer { Task { await socket.shutdown() } }

        let envelope = AdminAction(
            domain: AdminActionVerifier.expectedDomain,
            action: .revokeAllBots,
            nonce: "NNNNNNNNNNNNNNNNNNNNN2",
            issuedAt: Date(),
            actor: "Fr0zenSide@obyw.one"
        )
        let sig = try Data(adminKey.signature(for: envelope.canonicalBytes()))
        let signed = SignedAdminAction(envelope: envelope, signature: sig)

        let revoked = try await daemon.revokeAllBots(signedBy: signed)
        #expect(revoked == 2)

        // Registry rows are revoked.
        #expect(await registry.isRevoked(jti: seededJtiA) == true)
        #expect(await registry.isRevoked(jti: seededJtiB) == true)

        // Seam row carries the actor + nonce.
        let rows = await seams.all()
        #expect(!rows.isEmpty)
        let last = try #require(rows.last)
        #expect(last.outcome == .bypassed)
        let notes = try #require(last.notes)
        #expect(notes.contains("Fr0zenSide@obyw.one"))
        #expect(notes.contains("NNNNNNNNNNNNNNNNNNNNN2"))
        // Seams row MUST NOT leak signature bytes.
        #expect(!notes.contains(sig.base64EncodedString()))
    }

    @Test("a manifest-domain signature is rejected when replayed as an admin action")
    func test_brokerDaemon_revokeAllBots_manifestSignatureReplayedAsAdmin_rejected() async throws {
        let sharedKey = Curve25519.Signing.PrivateKey()
        let (daemon, socket, _, registry) = try await makeDaemon(
            adminPublicKey: sharedKey.publicKey
        )
        defer { Task { await socket.shutdown() } }

        // Build an envelope that WOULD be a legitimate manifest-class
        // signed payload (same key bytes, different `domain`). The
        // broker MUST reject it even though the signature is valid
        // for the manifest domain.
        let manifestDomainEnvelope = AdminAction(
            domain: "shikki.mcp.manifest.v1",
            action: .revokeAllBots,
            nonce: "NNNNNNNNNNNNNNNNNNNNN3",
            issuedAt: Date(),
            actor: "Fr0zenSide@obyw.one"
        )
        let bytes = try manifestDomainEnvelope.canonicalBytes()
        let sig = try Data(sharedKey.signature(for: bytes))
        let signed = SignedAdminAction(
            envelope: manifestDomainEnvelope, signature: sig
        )

        // The daemon MUST refuse. Domain separation (BR-F-09) is the
        // only thing preventing this replay — the signature itself is
        // cryptographically valid.
        await #expect(throws: BrokerDaemonError.adminSignatureInvalid) {
            _ = try await daemon.revokeAllBots(signedBy: signed)
        }
        #expect(await registry.isRevoked(jti: seededJtiA) == false)
        #expect(await registry.isRevoked(jti: seededJtiB) == false)
    }
}
