import Foundation
import Testing
@testable import ShiSecretsKit

// TokenRegistry revoke tests (Task 14 — BR-A-10, BR-F-06, BR-J-06).
//
// revoke(jti:) sets revoked=TRUE + revoked_at; isRevoked returns the
// flag. Single-jti revoke MUST NOT cascade to other tokens sharing the
// same sub. Revoked rows are retained indefinitely for audit (never
// hard-deleted by the broker).

@Suite("TokenRegistryRevoke")
struct TokenRegistryRevokeTests {

    private static let jtiA = "01JABCDEFGHJKMNPQRSTVWXYZ0"
    private static let jtiB = "01JABCDEFGHJKMNPQRSTVWXYZ1"

    private func row(jti: String, sub: String, passkey: Bool = false) -> TokenRegistry.Row {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        return TokenRegistry.Row(
            jti: jti, sub: sub, scope: "ovh/*", op: .read,
            nbf: now, diesAt: now.addingTimeInterval(3600),
            llmTouched: false, passkeyPath: passkey
        )
    }

    @Test("revoked jti rejected regardless of dies_at")
    func token_revokedJti_rejectedRegardlessOfDiesAt() async throws {
        let reg = TokenRegistry()
        try await reg.insert(row(jti: Self.jtiA, sub: "bot:x"))
        try await reg.revoke(jti: Self.jtiA)
        #expect(await reg.isRevoked(jti: Self.jtiA) == true)
        let stored = try #require(await reg.row(jti: Self.jtiA))
        #expect(stored.revoked == true)
        #expect(stored.revokedAt != nil)
    }

    @Test("revoke(jti:) — no cascade to other tokens sharing same sub")
    func revokeSingleJti_doesNotCascadeToOtherTokensSharingSameSub() async throws {
        let reg = TokenRegistry()
        try await reg.insert(row(jti: Self.jtiA, sub: "bot:shared"))
        try await reg.insert(row(jti: Self.jtiB, sub: "bot:shared"))
        try await reg.revoke(jti: Self.jtiA)
        #expect(await reg.isRevoked(jti: Self.jtiA) == true)
        #expect(await reg.isRevoked(jti: Self.jtiB) == false)
    }

    @Test("revoked rows retained indefinitely — not hard-deleted")
    func schema_tokenRegistry_revokedRowsRetainedIndefinitely_notHardDeleted() async throws {
        let reg = TokenRegistry()
        try await reg.insert(row(jti: Self.jtiA, sub: "bot:x"))
        try await reg.revoke(jti: Self.jtiA)
        // The row must still be retrievable after revocation.
        let still = try #require(await reg.row(jti: Self.jtiA))
        #expect(still.revoked == true)
        let all = await reg.all()
        #expect(all.count == 1)
    }
}
