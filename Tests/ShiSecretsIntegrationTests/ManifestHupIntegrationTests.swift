import Crypto
import Foundation
@testable import ShiSecretsBrokerd
import ShiSecretsKit
import Testing

// T70 — Integration: Manifest HUP reload — valid vs bad-sig paths.

@Suite("ManifestHupIntegration")
struct ManifestHupIntegrationTests {

    @Test("HUP reload — valid signature — pinned manifest refreshed in-memory")
    func test_integration_manifestHupReload_validSig_refreshesInMemorySchema() async throws {
        let stack = try await IntegSupport.makeStack()
        defer { Task { await IntegSupport.tearDown(stack) } }

        // Load initial + HUP-reload with a fresh manifest version signed
        // by the pinned private key.
        let (bytes1, sig1) = try IntegSupport.signedManifest(
            using: stack.manifestPrivateKey,
            version: "v1.0",
            tools: []
        )
        try await stack.manifestStore.loadInitial(bytes: bytes1, signature: sig1)
        #expect(await stack.manifestStore.current()?.version == "v1.0")

        let (bytes2, sig2) = try IntegSupport.signedManifest(
            using: stack.manifestPrivateKey,
            version: "v1.1",
            tools: []
        )
        await stack.daemon.handleHUP(bytes: bytes2, signature: sig2)
        #expect(await stack.manifestStore.current()?.version == "v1.1")
    }

    @Test("HUP reload — bad signature — broker keeps pinned + seams row written")
    func test_integration_manifestBadSigOnHup_brokerKeepsServingPinned_seamsRowWritten() async throws {
        let stack = try await IntegSupport.makeStack()
        defer { Task { await IntegSupport.tearDown(stack) } }

        let (bytes1, sig1) = try IntegSupport.signedManifest(
            using: stack.manifestPrivateKey,
            version: "v1.0"
        )
        try await stack.manifestStore.loadInitial(bytes: bytes1, signature: sig1)

        // Forge a HUP with a garbage signature.
        await stack.daemon.handleHUP(bytes: bytes1, signature: Data([0xDE, 0xAD]))
        #expect(await stack.manifestStore.current()?.version == "v1.0", "pinned retained")

        let seams = await stack.seams.all()
        let hadManifestSigFailRow = seams.contains { row in
            if case .manifestSigFailed = row.signal { return true }
            return false
        }
        #expect(hadManifestSigFailRow)
    }
}
