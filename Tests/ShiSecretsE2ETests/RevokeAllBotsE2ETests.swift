import Foundation
@testable import ShiSecretsBrokerd
import ShiSecretsKit
import Testing

// T74 — E2E: revoke-all-bots cuts bot tokens; passkey-path token stays valid.

@Suite("RevokeAllBotsE2E")
struct RevokeAllBotsE2ETests {

    @Test("shi token revoke --all-bots — cuts all bot access; passkey path still works")
    func test_e2e_shiTokenRevokeAllBots_cutsAllBotAccess_passkeyPathStillWorks() async throws {
        let stack = try await E2ESupport.make()
        defer { Task { await E2ESupport.tearDown(stack) } }

        let baseNbf = Date()
        let diesAt = baseNbf.addingTimeInterval(1200)
        // Seed: 3 bot tokens + 1 passkey token.
        let rows: [TokenRegistry.Row] = [
            .init(jti: "01JC0A0000000000000000BT11", sub: "ci@nuc-dev",
                  scope: "ovh/*", op: .read, nbf: baseNbf, diesAt: diesAt,
                  llmTouched: false, passkeyPath: false),
            .init(jti: "01JC0A0000000000000000BT22", sub: "ci@nuc-dev",
                  scope: "brevo/*", op: .read, nbf: baseNbf, diesAt: diesAt,
                  llmTouched: false, passkeyPath: false),
            .init(jti: "01JC0A0000000000000000BT33", sub: "mcp@claude",
                  scope: "github/*", op: .read, nbf: baseNbf, diesAt: diesAt,
                  llmTouched: true, passkeyPath: false),
            .init(jti: "01JC0A0000000000000PASSKEY", sub: "user@passkey",
                  scope: "ovh/*", op: .read, nbf: baseNbf, diesAt: diesAt,
                  llmTouched: false, passkeyPath: true),
        ]
        for row in rows {
            try await stack.registry.insert(row)
        }

        let count = try await stack.registry.revokeAllBots()
        #expect(count == 3)

        // Every bot row is revoked.
        for i in 0..<3 {
            let bot = await stack.registry.isRevoked(jti: rows[i].jti)
            #expect(bot, "bot row \(rows[i].jti) should be revoked")
        }
        // Passkey row still valid.
        let passkey = await stack.registry.isRevoked(jti: rows[3].jti)
        #expect(!passkey, "passkey row MUST NOT be revoked")
    }
}
