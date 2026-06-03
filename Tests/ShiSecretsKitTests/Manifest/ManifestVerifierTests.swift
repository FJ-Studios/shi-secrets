import Crypto
import Foundation
import Testing
@testable import ShiSecretsKit

// ManifestVerifier tests (Task 24 — BR-H-02a, BR-H-02b).
//
// The MCP manifest is an Ed25519-signed JSON list of ToolEntry records.
// The broker pins the verification *public* key at provisioning time and
// NEVER possesses the signing private key (BR-H-02b). Signing is
// performed by an external tool (`shikki-manifest-sign`) under the
// Daimyo's passkey user-presence (BR-H-02c — guarded in Task 26).

@Suite("ManifestVerifier")
struct ManifestVerifierTests {

    /// Fixture: a valid manifest + matching signature + pinned pubkey.
    /// Generated fresh per-test so no long-lived key material is checked
    /// into the repo.
    private func fixture() throws -> (
        verifier: ManifestVerifier,
        manifestBytes: Data,
        signature: Data
    ) {
        let privateKey = Curve25519.Signing.PrivateKey()
        let verifier = ManifestVerifier(pinnedPublicKey: privateKey.publicKey)

        let manifest = ManifestVerifier.Manifest(
            version: "1.0.0",
            issuedAt: Date(timeIntervalSince1970: 1_700_000_000),
            tools: [
                ManifestVerifier.ToolEntry(
                    toolName: "secrets.request_token",
                    schemaHash: "sha256:abc123",
                    scopeGlob: "ovh/*",
                    maxTtl: 600,
                    op: .read
                ),
                ManifestVerifier.ToolEntry(
                    toolName: "secrets.list_accessible",
                    schemaHash: "sha256:def456",
                    scopeGlob: "**",
                    maxTtl: 300,
                    op: .read
                ),
            ]
        )
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        let bytes = try encoder.encode(manifest)
        let sig = try privateKey.signature(for: bytes)
        return (verifier, bytes, Data(sig))
    }

    @Test("schema shape: Ed25519-signed JSON list of tool entries")
    func mcpManifest_schemaShape_ed25519SignedJsonListOfToolEntries() throws {
        let (verifier, bytes, sig) = try fixture()
        let manifest = try verifier.verify(manifestBytes: bytes, signatureBytes: sig)
        #expect(manifest.tools.count == 2)
        #expect(manifest.version == "1.0.0")
    }

    @Test("entry fields: tool_name, schema_hash, scope_glob, max_ttl, op")
    func mcpManifest_entryFields_toolName_schemaHash_scopeGlob_maxTtl() throws {
        let (verifier, bytes, sig) = try fixture()
        let manifest = try verifier.verify(manifestBytes: bytes, signatureBytes: sig)
        let first = try #require(manifest.tools.first)
        #expect(first.toolName == "secrets.request_token")
        #expect(first.schemaHash == "sha256:abc123")
        #expect(first.scopeGlob == "ovh/*")
        #expect(first.maxTtl == 600)
        #expect(first.op == .read)
    }

    @Test("broker never possesses manifest signing private key — only public pinned")
    func broker_neverPossessesManifestSigningPrivateKey_onlyPublicPinned() throws {
        // The verifier's sole input is a Curve25519.Signing.PublicKey —
        // no private-key slot exists on ManifestVerifier. Verification
        // path succeeds with a matching pubkey but has no signing
        // capability.
        let (verifier, bytes, sig) = try fixture()
        _ = try verifier.verify(manifestBytes: bytes, signatureBytes: sig)

        // Swapping the pinned key to a fresh (unrelated) pubkey rejects
        // the signature — proving the verifier never mints or coerces
        // its own key material.
        let otherKey = Curve25519.Signing.PrivateKey().publicKey
        let rogue = ManifestVerifier(pinnedPublicKey: otherKey)
        #expect(throws: ManifestVerifier.VerifyError.self) {
            _ = try rogue.verify(manifestBytes: bytes, signatureBytes: sig)
        }
    }
}
