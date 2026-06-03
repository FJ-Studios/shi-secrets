import Foundation
import Testing
@testable import ShiSecretsKit

// revokeAllBots tests (Task 15 — BR-F-01, BR-F-02).
//
// `shi token revoke --all-bots` revokes every non-passkey row in a
// single atomic transaction. Passkey-path rows are untouched — the
// human passkey flow keeps working even during a full bot nuke.
// On any failure the whole transaction rolls back.

@Suite("RevokeAllBots")
struct RevokeAllBotsTests {

    private func row(
        jti: String,
        sub: String,
        passkey: Bool = false
    ) -> TokenRegistry.Row {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        return TokenRegistry.Row(
            jti: jti, sub: sub, scope: "ovh/*", op: .read,
            nbf: now, diesAt: now.addingTimeInterval(3600),
            llmTouched: false, passkeyPath: passkey
        )
    }

    // 26-char Crockford ULIDs. Trailing suffix varies to differentiate.
    private static let ulids: [String] = [
        "01JABCDEFGHJKMNPQRSTVWXYZ0",
        "01JABCDEFGHJKMNPQRSTVWXYZ1",
        "01JABCDEFGHJKMNPQRSTVWXYZ2",
        "01JABCDEFGHJKMNPQRSTVWXYZ3",
    ]

    @Test("revokes every non-passkey token in a single atomic TX")
    func revokeAllBots_revokesEveryNonPasskeyTokenInSingleAtomicTransaction() async throws {
        let reg = TokenRegistry()
        try await reg.insert(row(jti: Self.ulids[0], sub: "bot:ovh"))
        try await reg.insert(row(jti: Self.ulids[1], sub: "bot:brevo"))
        try await reg.insert(row(jti: Self.ulids[2], sub: "bot:gh"))
        try await reg.insert(row(jti: Self.ulids[3], sub: "human:daimyo", passkey: true))

        let count = try await reg.revokeAllBots()
        #expect(count == 3)
        #expect(await reg.isRevoked(jti: Self.ulids[0]) == true)
        #expect(await reg.isRevoked(jti: Self.ulids[1]) == true)
        #expect(await reg.isRevoked(jti: Self.ulids[2]) == true)
        #expect(await reg.isRevoked(jti: Self.ulids[3]) == false)
    }

    @Test("atomic — partial failure rolls back entire transaction")
    func revokeAllBots_atomicity_partialFailureRollsBack() async throws {
        let reg = TokenRegistry()
        try await reg.insert(row(jti: Self.ulids[0], sub: "bot:ovh"))
        try await reg.insert(row(jti: Self.ulids[1], sub: "bot:brevo"))
        try await reg.insert(row(jti: Self.ulids[2], sub: "bot:gh"))

        // Inject a failure on the brevo row. On rollback none of the
        // rows should be marked revoked.
        await #expect(throws: TokenRegistry.TransactionError.self) {
            try await reg.revokeAllBots { $0.sub == "bot:brevo" }
        }
        #expect(await reg.isRevoked(jti: Self.ulids[0]) == false)
        #expect(await reg.isRevoked(jti: Self.ulids[1]) == false)
        #expect(await reg.isRevoked(jti: Self.ulids[2]) == false)
    }

    @Test("does not touch passkey-path tokens")
    func revokeAllBots_doesNotTouchPasskeyPathTokens() async throws {
        let reg = TokenRegistry()
        try await reg.insert(row(jti: Self.ulids[0], sub: "human:daimyo", passkey: true))
        try await reg.insert(row(jti: Self.ulids[1], sub: "bot:ovh"))

        let count = try await reg.revokeAllBots()
        #expect(count == 1)
        #expect(await reg.isRevoked(jti: Self.ulids[0]) == false)
        #expect(await reg.isRevoked(jti: Self.ulids[1]) == true)
    }
}
