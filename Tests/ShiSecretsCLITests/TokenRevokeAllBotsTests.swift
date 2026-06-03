import Crypto
import Foundation
@testable import ShiSecretsCLI
import ShiSecretsClient
import ShiSecretsKit
import Testing

@Suite("TokenRevokeAllBots")
struct TokenRevokeAllBotsTests {

    @Test("interactive — renders blast-radius dry-run + requires y/N confirmation")
    func test_revokeAllBots_interactive_rendersBlastRadiusDryRun_requiresConfirmation() async throws {
        let client = RecordingBrokerClient()
        await client.setRevokeAllBotsResponse(RevokeAllBotsResult(revokedCount: 7, passkeyPreservedCount: 2))
        let prompt = ScriptedPromptReader(responses: ["y"])
        let seams = InMemorySeamsRecorder()
        let cmd = TokenCommand(client: client, prompt: prompt, seams: seams)
        let out = try await cmd.runRevoke(args: ["--all-bots"])

        #expect(out.stdout.contains("dry-run: would revoke 7 bot tokens"))
        #expect(out.stdout.contains("preserve 2 passkey-path tokens"))
        #expect(out.stdout.contains("proceed? [y/N]"))
        #expect(out.stdout.contains("revoked 7 bot tokens"))

        let calls = await client.revokeAllBotsCalls
        // Expect two calls: one dry-run, one apply.
        #expect(calls.count == 2)
        #expect(calls[0].dryRun == true)
        #expect(calls[1].dryRun == false)
        #expect(calls[1].force == false)

        let seamEvents = await seams.snapshot()
        #expect(seamEvents.isEmpty)  // no incident_bypass on interactive path
    }

    @Test("--force alone is retired (item #9) — CLI refuses with adminSignatureRequired")
    func test_revokeAllBots_forceFlag_retired_adminSignatureRequired() async throws {
        let client = RecordingBrokerClient()
        await client.setRevokeAllBotsResponse(RevokeAllBotsResult(revokedCount: 12, passkeyPreservedCount: 3))
        let prompt = ScriptedPromptReader(responses: [])
        let seams = InMemorySeamsRecorder()
        let cmd = TokenCommand(client: client, prompt: prompt, seams: seams)

        await #expect(throws: TokenCommandError.adminSignatureRequired) {
            _ = try await cmd.runRevoke(args: ["--all-bots", "--force"])
        }
        // Neither dry-run nor apply should have been issued.
        let calls = await client.revokeAllBotsCalls
        #expect(calls.isEmpty)
        let seamEvents = await seams.snapshot()
        #expect(seamEvents.isEmpty)
    }

    @Test("--signed-envelope delegates to revokeAllBotsSigned")
    func test_revokeAllBots_signedEnvelope_delegatesToBroker() async throws {
        let client = RecordingBrokerClient()
        await client.setRevokeAllBotsResponse(RevokeAllBotsResult(revokedCount: 9, passkeyPreservedCount: 1))
        let prompt = ScriptedPromptReader(responses: [])
        let seams = InMemorySeamsRecorder()
        let cmd = TokenCommand(client: client, prompt: prompt, seams: seams)

        // Build a real SignedAdminAction payload (CLI does not verify
        // — that's the broker's job — but it must decode the JSON).
        let signingKey = Curve25519.Signing.PrivateKey()
        let envelope = AdminAction(
            domain: AdminActionVerifier.expectedDomain,
            action: .revokeAllBots,
            nonce: "CLITESTNONCE0000000001",
            issuedAt: Date(timeIntervalSince1970: 1_700_000_000),
            actor: "Fr0zenSide@obyw.one"
        )
        let sig = try Data(signingKey.signature(for: envelope.canonicalBytes()))
        let signed = SignedAdminAction(envelope: envelope, signature: sig)

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let bytes = try encoder.encode(signed)

        let reader: @Sendable (String) async throws -> Data = { path in
            #expect(path == "-")
            return bytes
        }

        let out = try await cmd.runRevoke(
            args: ["--all-bots", "--signed-envelope", "-"],
            envelopeReader: reader
        )
        #expect(out.stdout.contains("revoked 9 bot tokens"))
        #expect(out.stdout.contains("signed by Fr0zenSide@obyw.one"))

        let recorded = await client.revokeAllBotsSignedCalls
        #expect(recorded.count == 1)
        #expect(recorded.first?.envelope.nonce == "CLITESTNONCE0000000001")
    }

    @Test("interactive — prompt snapshot covers dry-run summary + y/N question")
    func test_cli_revokeAllBots_interactivePrompt_snapshot() async throws {
        let client = RecordingBrokerClient()
        await client.setRevokeAllBotsResponse(RevokeAllBotsResult(revokedCount: 5, passkeyPreservedCount: 1))
        let prompt = ScriptedPromptReader(responses: ["n"])   // decline → abort
        let seams = InMemorySeamsRecorder()
        let cmd = TokenCommand(client: client, prompt: prompt, seams: seams)
        let out = try await cmd.runRevoke(args: ["--all-bots"])
        let expectedPrefix = """
        dry-run: would revoke 5 bot tokens
                 preserve 1 passkey-path tokens
        proceed? [y/N]: aborted.
        """
        #expect(out.stdout.hasPrefix(expectedPrefix))
        // No apply call was made — only the dry-run.
        let calls = await client.revokeAllBotsCalls
        #expect(calls.count == 1)
        #expect(calls.first?.dryRun == true)
    }
}
