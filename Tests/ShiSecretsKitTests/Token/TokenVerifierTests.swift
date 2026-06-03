import Crypto
import Foundation
import Testing
@testable import ShiSecretsKit

// TokenVerifier tests (Task 19 — BR-A-08, BR-A-09, BR-A-10, BR-A-12).
//
// verify(token:at:) performs signature → nbf ≤ now ≤ diesAt → revoked
// in order; each failure returns a DenyReason AND appends exactly one
// audit row (BR-G-01) before the deny response is returned.

@Suite("TokenVerifier")
struct TokenVerifierTests {

    private struct Harness {
        let minter: TokenMinter
        let registry: TokenRegistry
        let verifier: TokenVerifier
        let audit: AuditWriter
        let signingKey: Curve25519.Signing.PrivateKey
    }

    private func makeHarness() -> Harness {
        let signingKey = Curve25519.Signing.PrivateKey()
        let registry = TokenRegistry()
        let audit = AuditWriter()
        let minter = TokenMinter(
            registry: registry,
            signingKey: signingKey,
            toolManifest: []
        )
        let verifier = TokenVerifier(
            registry: registry,
            audit: audit,
            publicKey: signingKey.publicKey
        )
        return Harness(
            minter: minter,
            registry: registry,
            verifier: verifier,
            audit: audit,
            signingKey: signingKey
        )
    }

    @Test("presented after dies_at → tokenExpired + audit row written")
    func token_presentedAfterDiesAt_rejectedAsExpired_auditRowWritten() async throws {
        let h = makeHarness()
        let nbf = Date(timeIntervalSince1970: 1_700_000_000)
        let token = try await h.minter.mint(
            request: .init(sub: "bot:x", scope: "ovh/*", op: .read, ttl: 600, toolName: nil),
            transport: .unix,
            peerUid: 1001,
            now: nbf
        )
        let afterDeath = nbf.addingTimeInterval(601)
        let reason = await h.verifier.verify(
            token: token,
            at: afterDeath,
            callerUid: 1001,
            transport: .unix,
            secretName: "ovh:dns"
        )
        #expect(reason == .tokenExpired)
        let rows = await h.audit.all()
        #expect(rows.count == 1)
        #expect(rows.first?.reason == .tokenExpired)
    }

    @Test("presented before nbf → tokenNotYetValid + audit row")
    func token_presentedBeforeNbf_rejectedAsNotYetValid_auditRowWritten() async throws {
        let h = makeHarness()
        let nbf = Date(timeIntervalSince1970: 1_700_000_000)
        let token = try await h.minter.mint(
            request: .init(sub: "bot:x", scope: "ovh/*", op: .read, ttl: 600, toolName: nil),
            transport: .unix,
            peerUid: 1001,
            now: nbf
        )
        let beforeBirth = nbf.addingTimeInterval(-5)
        let reason = await h.verifier.verify(
            token: token,
            at: beforeBirth,
            callerUid: 1001,
            transport: .unix,
            secretName: "ovh:dns"
        )
        #expect(reason == .tokenNotYetValid)
        #expect(await h.audit.all().count == 1)
    }

    @Test("bad signature → badSignature deny reason")
    func token_badSignature_rejectedWithDenyReasonBadSignature() async throws {
        let h = makeHarness()
        let nbf = Date(timeIntervalSince1970: 1_700_000_000)
        let good = try await h.minter.mint(
            request: .init(sub: "bot:x", scope: "ovh/*", op: .read, ttl: 600, toolName: nil),
            transport: .unix,
            peerUid: 1001,
            now: nbf
        )
        // Flip one byte in the envelope to invalidate the Ed25519 sig.
        var tampered = good.envelope
        if !tampered.isEmpty {
            tampered[tampered.startIndex] ^= 0x01
        }
        let badToken = TokenMinter.Token(claims: good.claims, envelope: tampered)
        let reason = await h.verifier.verify(
            token: badToken,
            at: nbf,
            callerUid: 1001,
            transport: .unix,
            secretName: "ovh:dns"
        )
        #expect(reason == .badSignature)
    }

    @Test("clock rollback → tokenClockRollback (U8)")
    func test_tokenVerifier_clockRollback_rejected_U8() async throws {
        // Review finding U8 — a caller-supplied `now` that moves
        // backwards vs the verifier's monotonic floor is rejected.
        let h = makeHarness()
        let nbf = Date(timeIntervalSince1970: 1_700_000_000)
        let token = try await h.minter.mint(
            request: .init(sub: "bot:x", scope: "ovh/*", op: .read, ttl: 600, toolName: nil),
            transport: .unix, peerUid: 1001, now: nbf
        )
        // First call at nbf — succeeds, advances floor.
        let first = await h.verifier.verify(
            token: token, at: nbf, callerUid: 1001, transport: .unix, secretName: "s"
        )
        #expect(first == nil)
        // Second call at nbf - 60 — rollback detected.
        let second = await h.verifier.verify(
            token: token, at: nbf.addingTimeInterval(-60),
            callerUid: 1001, transport: .unix, secretName: "s"
        )
        #expect(second == .tokenClockRollback)
    }

    @Test("revoke-vs-verify race closed by epoch check (U4)")
    func test_tokenVerifier_revokeVsVerifyRace_closedByEpochCheck_U4() async throws {
        // Review finding U4 — if `revokeAllBots` bumps the registry
        // epoch after the initial isRevoked() read but before verify
        // returns, the exit epoch check re-consults the registry. If
        // the jti is now revoked, verify returns `.tokenRevoked`.
        let h = makeHarness()
        let nbf = Date(timeIntervalSince1970: 1_700_000_000)
        let token = try await h.minter.mint(
            request: .init(sub: "bot:x", scope: "ovh/*", op: .read, ttl: 600, toolName: nil),
            transport: .unix, peerUid: 1001, now: nbf
        )
        // Sanity — baseline epoch snapshots.
        let epoch1 = await h.registry.revokeEpoch
        _ = try await h.registry.revokeAllBots(at: nbf)
        let epoch2 = await h.registry.revokeEpoch
        #expect(epoch2 > epoch1)

        // After revokeAll, a fresh verify must return .tokenRevoked.
        let reason = await h.verifier.verify(
            token: token, at: nbf.addingTimeInterval(5),
            callerUid: 1001, transport: .unix, secretName: "s"
        )
        #expect(reason == .tokenRevoked)
    }

    @Test("revoked jti → tokenRevoked regardless of dies_at")
    func token_revokedJti_rejectedRegardlessOfDiesAt() async throws {
        let h = makeHarness()
        let nbf = Date(timeIntervalSince1970: 1_700_000_000)
        let token = try await h.minter.mint(
            request: .init(sub: "bot:x", scope: "ovh/*", op: .read, ttl: 600, toolName: nil),
            transport: .unix,
            peerUid: 1001,
            now: nbf
        )
        try await h.registry.revoke(jti: token.claims.jti)
        let reason = await h.verifier.verify(
            token: token,
            at: nbf.addingTimeInterval(10),    // well within dies_at
            callerUid: 1001,
            transport: .unix,
            secretName: "ovh:dns"
        )
        #expect(reason == .tokenRevoked)
    }
}
