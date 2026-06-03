import Crypto
import Foundation
import Testing
@testable import ShiSecretsKit

// AdminActionVerifier tests (item #9 — BR-F-08 / BR-F-09 / BR-F-10 / BR-F-11).
//
// The verifier gates privileged broker commands (currently:
// revoke-all-bots) behind an Ed25519-signed envelope produced by the
// operator's Mac Secure Enclave. Verification checks:
//   - domain field equals "shikki.admin.action.v1" (BR-F-09)
//   - freshness window is ±60s (BR-F-11)
//   - nonce has not been seen before (BR-F-10)
//   - signature verifies against the pinned admin public key (BR-F-08)
//
// The pinned key MAY be the same bytes as the MCP manifest pubkey but
// the signed domain MUST differ — a manifest signature cannot be
// replayed as an admin action.

@Suite("AdminActionVerifier")
struct AdminActionVerifierTests {

    /// Build a freshly-signed envelope + return it with the verifier that
    /// pins its corresponding public key. Tests mutate the envelope or
    /// the signature to exercise negative paths.
    private func fixture(
        action: AdminAction.ActionKind = .revokeAllBots,
        domain: String = AdminActionVerifier.expectedDomain,
        issuedAt: Date = Date(timeIntervalSince1970: 1_700_000_000),
        nonce: String = "AAAAAAAAAAAAAAAAAAAAAA",
        actor: String = "Fr0zenSide@obyw.one",
        clock: @escaping @Sendable () -> Date = {
            Date(timeIntervalSince1970: 1_700_000_000)
        }
    ) throws -> (
        verifier: AdminActionVerifier,
        envelope: AdminAction,
        signature: Data,
        signingKey: Curve25519.Signing.PrivateKey
    ) {
        let signingKey = Curve25519.Signing.PrivateKey()
        let verifier = AdminActionVerifier(
            pinnedPublicKey: signingKey.publicKey,
            clock: clock
        )
        let envelope = AdminAction(
            domain: domain,
            action: action,
            nonce: nonce,
            issuedAt: issuedAt,
            actor: actor
        )
        let bytes = try envelope.canonicalBytes()
        let sig = try signingKey.signature(for: bytes)
        return (verifier, envelope, Data(sig), signingKey)
    }

    @Test("verify happy path returns action kind")
    func test_adminAction_verify_happyPath_returnsActionKind() async throws {
        let (verifier, envelope, sig, _) = try fixture()
        let signed = SignedAdminAction(envelope: envelope, signature: sig)
        let kind = try await verifier.verify(signed)
        #expect(kind == .revokeAllBots)
    }

    @Test("verify rejects a bad signature")
    func test_adminAction_verify_badSignature_rejected() async throws {
        let (verifier, envelope, sig, _) = try fixture()
        // Flip one byte of the signature — any single-bit mutation
        // invalidates an Ed25519 signature.
        var tampered = sig
        tampered[0] ^= 0xFF
        let signed = SignedAdminAction(envelope: envelope, signature: tampered)
        await #expect(throws: AdminActionVerifier.VerifyError.badSignature) {
            _ = try await verifier.verify(signed)
        }
    }

    @Test(
        "verify rejects a bad domain",
        arguments: ["wrong", "shikki.mcp.manifest.v1", ""]
    )
    func test_adminAction_verify_badDomain_rejected(domain: String) async throws {
        let (verifier, envelope, sig, _) = try fixture(domain: domain)
        let signed = SignedAdminAction(envelope: envelope, signature: sig)
        await #expect(throws: AdminActionVerifier.VerifyError.self) {
            _ = try await verifier.verify(signed)
        }
        // Confirm it's the `.badDomain(...)` variant specifically.
        do {
            _ = try await verifier.verify(signed)
            Issue.record("expected throw")
        } catch AdminActionVerifier.VerifyError.badDomain(let got) {
            #expect(got == domain)
        } catch {
            Issue.record("wrong error: \(error)")
        }
    }

    @Test("verify rejects a stale timestamp (issuedAt = now − 120s)")
    func test_adminAction_verify_staleTimestamp_rejected() async throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let issuedAt = now.addingTimeInterval(-120)
        let (verifier, envelope, sig, _) = try fixture(
            issuedAt: issuedAt,
            clock: { now }
        )
        let signed = SignedAdminAction(envelope: envelope, signature: sig)
        await #expect(throws: AdminActionVerifier.VerifyError.self) {
            _ = try await verifier.verify(signed)
        }
        do {
            _ = try await verifier.verify(signed)
            Issue.record("expected throw")
        } catch AdminActionVerifier.VerifyError.stale(let gotIssued, let gotNow, let skew) {
            #expect(gotIssued == issuedAt)
            #expect(gotNow == now)
            #expect(skew == AdminActionVerifier.maxSkewSeconds)
        } catch {
            Issue.record("wrong error: \(error)")
        }
    }

    @Test("verify rejects a replayed nonce on the second use")
    func test_adminAction_verify_replayedNonce_rejectedOnSecondUse() async throws {
        let (verifier, envelope, sig, _) = try fixture(nonce: "BBBBBBBBBBBBBBBBBBBBBB")
        let signed = SignedAdminAction(envelope: envelope, signature: sig)
        // First use: ok.
        _ = try await verifier.verify(signed)
        // Second use: rejected.
        await #expect(throws: AdminActionVerifier.VerifyError.self) {
            _ = try await verifier.verify(signed)
        }
        do {
            _ = try await verifier.verify(signed)
            Issue.record("expected throw")
        } catch AdminActionVerifier.VerifyError.replay(let nonce) {
            #expect(nonce == "BBBBBBBBBBBBBBBBBBBBBB")
        } catch {
            Issue.record("wrong error: \(error)")
        }
    }
}
