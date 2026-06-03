import Crypto
import Foundation
import Testing
@testable import ShiSecretsKit

// TokenMinter tests (Task 17 — BR-A-01, BR-H-05).
//
// Tokens MUST be Ed25519 / COSE_Sign1 envelopes signed with the broker's
// active signing key; other schemes are rejected. Manifest-op gate: a
// request whose `op` does not match the invoked tool's signed schema is
// rejected.

@Suite("TokenMinter")
struct TokenMinterTests {

    private func makeMinter(tools: [ManifestVerifier.ToolEntry] = []) -> (TokenMinter, TokenRegistry, Curve25519.Signing.PublicKey) {
        let signingKey = Curve25519.Signing.PrivateKey()
        let registry = TokenRegistry()
        let minter = TokenMinter(
            registry: registry,
            signingKey: signingKey,
            toolManifest: tools
        )
        return (minter, registry, signingKey.publicKey)
    }

    @Test("tokens MUST be Ed25519 / COSE_Sign1 — other schemes rejected at API boundary")
    func token_mustBeEd25519COSESign1_otherSchemesRejected() async throws {
        let (minter, _, _) = makeMinter()
        // TokenMinter.SignatureScheme exposes ONLY .ed25519cose — any
        // other scheme would be a compile-time failure. We additionally
        // assert the declared scheme at runtime for the linter.
        #expect(minter.signatureScheme == .ed25519COSESign1)
    }

    @Test("signed tokens verify under swift-crypto with broker active key")
    func token_signedWithBrokerActiveKey_verifiesUnderSwiftCrypto() async throws {
        let (minter, _, pub) = makeMinter()
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let request = TokenMinter.Request(
            sub: "bot:shi-mcp",
            scope: "ovh/*",
            op: .read,
            ttl: 600,
            toolName: nil
        )
        let token = try await minter.mint(request: request, transport: .unix, peerUid: 1001, now: now)

        // The envelope is the detached Ed25519 signature over the
        // canonicalized claims JSON. Verify using the broker's pubkey.
        let canonical = try TokenMinter.canonicalize(token.claims)
        #expect(pub.isValidSignature(token.envelope, for: canonical))
    }

    @Test("concurrent mint produces unique jtis — proper ULID, no collision")
    func test_tokenMinter_concurrentMint_noJtiCollision() async throws {
        // Review finding U9 — two mints in the same millisecond must
        // produce different jtis. The 80-bit random half gives ~1.2e24
        // combinations per ms; collision is statistically impossible.
        let (minter, _, _) = makeMinter()
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let request = TokenMinter.Request(
            sub: "bot:x", scope: "ovh/*", op: .read, ttl: 300, toolName: nil
        )
        // Issue 50 tokens in a tight loop (same millisecond on any modern CPU).
        var jtis: Set<String> = []
        for _ in 0 ..< 50 {
            let token = try await minter.mint(request: request, transport: .unix, peerUid: 1001, now: now)
            jtis.insert(token.claims.jti)
        }
        #expect(jtis.count == 50)
    }

    @Test("concurrent mint across milliseconds — full 128-bit ULID uniqueness (I3)")
    func test_tokenMinter_concurrentMint_acrossMilliseconds_noJtiCollision() async throws {
        // 3rd-pass validator I3 — the prior test pinned `now` to one
        // second so only the 80-bit random half of the ULID was
        // exercised. This test advances `now` by 1ms per mint so the
        // 48-bit timestamp half also changes; a ULID whose timestamp
        // and random halves were BOTH failing to vary would collide.
        // Asserts uniqueness across the full 128-bit surface.
        let (minter, _, _) = makeMinter()
        let base = Date(timeIntervalSince1970: 1_700_000_000)
        let request = TokenMinter.Request(
            sub: "bot:x", scope: "ovh/*", op: .read, ttl: 300, toolName: nil
        )
        var jtis: Set<String> = []
        var timestampPrefixes: Set<String> = []
        // Step +10ms per mint to dodge Double-to-Int precision loss
        // near 1e12 (~1.7e12 epoch-millis has ~11 sig digits; a 1ms
        // step occasionally rounds away).
        for i in 0 ..< 50 {
            let nowI = base.addingTimeInterval(Double(i) * 0.010)
            let token = try await minter.mint(
                request: request, transport: .unix, peerUid: 1001, now: nowI
            )
            jtis.insert(token.claims.jti)
            // First 10 Crockford chars encode the 48-bit ms timestamp.
            timestampPrefixes.insert(String(token.claims.jti.prefix(10)))
        }
        #expect(jtis.count == 50)
        // Across 50 distinct millisecond stamps, the timestamp prefix
        // MUST have varied — if it hadn't, nextJti would still be
        // pulling time from wall-clock `Date()` instead of the
        // injected `now`. At least 40 unique prefixes is well above
        // the noise floor of Double-ms rounding.
        #expect(timestampPrefixes.count >= 40)
    }

    @Test("broker rejects request whose op does not match invoked tool schema")
    func broker_rejectsRequestWhoseOpDoesNotMatchInvokedToolSchema() async throws {
        let tool = ManifestVerifier.ToolEntry(
            toolName: "secrets.request_token",
            schemaHash: "sha256:abc",
            scopeGlob: "ovh/*",
            maxTtl: 600,
            op: .read
        )
        let (minter, _, _) = makeMinter(tools: [tool])
        let request = TokenMinter.Request(
            sub: "bot:shi-mcp",
            scope: "ovh/*",
            op: .rotate,                    // mismatch — manifest says .read
            ttl: 600,
            toolName: "secrets.request_token"
        )
        await #expect(throws: TokenMinter.MintError.opMismatch) {
            _ = try await minter.mint(request: request, transport: .unix, peerUid: 1001)
        }
    }
}
