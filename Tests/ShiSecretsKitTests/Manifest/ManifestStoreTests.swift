import Crypto
import Foundation
import Testing
@testable import ShiSecretsKit

// ManifestStore tests (Task 25 — BR-H-02, BR-H-02d, BR-H-02e).
//
// loadInitial() throws on bad signature so the broker refuses to start.
// reload() keeps the previously-pinned manifest on bad signature and
// writes a `seams.manifestSigFailed` row (BR-H-02d fail-safe behavior).
// Direct edits to broker schema config without a re-signed manifest are
// rejected at HUP time (BR-H-02e).

@Suite("ManifestStore")
struct ManifestStoreTests {

    private struct Fixture {
        let privateKey: Curve25519.Signing.PrivateKey
        let verifier: ManifestVerifier
        let manifestBytes: Data
        let signature: Data
        let manifest: ManifestVerifier.Manifest

        init(version: String = "1.0.0") throws {
            self.privateKey = Curve25519.Signing.PrivateKey()
            self.verifier = ManifestVerifier(pinnedPublicKey: privateKey.publicKey)
            self.manifest = ManifestVerifier.Manifest(
                version: version,
                issuedAt: Date(timeIntervalSince1970: 1_700_000_000),
                tools: [
                    ManifestVerifier.ToolEntry(
                        toolName: "secrets.request_token",
                        schemaHash: "sha256:abc",
                        scopeGlob: "ovh/*",
                        maxTtl: 600,
                        op: .read
                    ),
                ]
            )
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            encoder.outputFormatting = [.sortedKeys]
            self.manifestBytes = try encoder.encode(manifest)
            self.signature = Data(try privateKey.signature(for: manifestBytes))
        }
    }

    @Test("verified at startup — bad sig blocks load")
    func mcpManifest_verifiedAtStartup_badSigBlocksLoad() async throws {
        let f = try Fixture()
        let seams = SeamsWriter()
        let store = ManifestStore(verifier: f.verifier, seams: seams)

        let bogus = Data(repeating: 0xAA, count: 64)
        await #expect(throws: ManifestVerifier.VerifyError.self) {
            try await store.loadInitial(bytes: f.manifestBytes, signature: bogus)
        }
        #expect(await store.current() == nil)
    }

    @Test("verified on HUP reload — bad sig rejected")
    func mcpManifest_verifiedOnHupReload_badSigRejected() async throws {
        let f = try Fixture()
        let seams = SeamsWriter()
        let store = ManifestStore(verifier: f.verifier, seams: seams)

        try await store.loadInitial(bytes: f.manifestBytes, signature: f.signature)
        let pinned = await store.current()
        #expect(pinned?.version == "1.0.0")

        // Reload with garbage — current must stay pinned, seams row written.
        let bogus = Data(repeating: 0xFF, count: 64)
        try await store.reload(bytes: f.manifestBytes, signature: bogus)
        #expect(await store.current()?.version == "1.0.0")
        let seamRows = await seams.all()
        #expect(seamRows.count == 1)
        if case .manifestSigFailed = seamRows.first?.signal {
            // OK
        } else {
            Issue.record("expected manifestSigFailed seams row")
        }
    }

    @Test("signature verify fail on reload — continues serving pinned + appends seams manifest_sig_failed")
    func mcpManifest_signatureVerifyFail_continuesServingPreviouslyPinned_appendsSeamsManifestSigFailed() async throws {
        let f = try Fixture()
        let seams = SeamsWriter()
        let store = ManifestStore(verifier: f.verifier, seams: seams)
        try await store.loadInitial(bytes: f.manifestBytes, signature: f.signature)

        // Build a *new* manifest (version 2.0.0) but sign it with a
        // different, unrecognized key. The store must refuse to swap
        // `current` and must append a seams row.
        let intruder = Curve25519.Signing.PrivateKey()
        let newFixture = try Fixture(version: "2.0.0")
        let badSig = Data(try intruder.signature(for: newFixture.manifestBytes))
        try await store.reload(bytes: newFixture.manifestBytes, signature: badSig)

        #expect(await store.current()?.version == "1.0.0")
        #expect(await seams.all().count == 1)
    }

    @Test("direct edit to broker schema config without re-signed manifest rejected at HUP")
    func brokerSchemaConfig_directEditWithoutReSignedManifest_rejectedAtHup() async throws {
        let f = try Fixture()
        let seams = SeamsWriter()
        let store = ManifestStore(verifier: f.verifier, seams: seams)
        try await store.loadInitial(bytes: f.manifestBytes, signature: f.signature)

        // Edit the manifest bytes in-place (simulating a `vim` edit on
        // disk) WITHOUT regenerating the signature. The old signature is
        // no longer valid for the mutated bytes.
        var tampered = f.manifestBytes
        if let firstByteIndex = tampered.indices.first {
            tampered[firstByteIndex] ^= 0x01
        }
        try await store.reload(bytes: tampered, signature: f.signature)
        // Previous pinned survives.
        #expect(await store.current()?.version == "1.0.0")
        #expect(await seams.all().count == 1)
    }
}
