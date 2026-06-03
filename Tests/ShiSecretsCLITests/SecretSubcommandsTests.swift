import Foundation
@testable import ShiSecretsCLI
import ShiSecretsClient
import ShiSecretsKit
import Testing

@Suite("SecretSubcommands")
struct SecretSubcommandsTests {

    @Test("shi secret — fetch/get/list/set/rotate/revoke all registered + alphabetically sorted")
    func test_cli_secret_subcommands_fetch_get_list_set_rotate_revoke_registered() {
        let names = SecretCommandRegistry.subcommandNames
        #expect(names == ["fetch", "get", "list", "revoke", "rotate", "set"])
    }

    @Test("fetch is a transparent alias for get — identical stdout + stderr")
    func test_cli_secret_fetch_aliasesGet_identicalOutput() async throws {
        let client = RecordingBrokerClient()
        await client.seedPlaintext("OVH_APP_KEY", "aliasPlaintext")
        let footerProvider: @Sendable (String) async -> InlineFooterContext? = { name in
            InlineFooterContext(
                variant: .normalWarm,
                age: "2d",
                tier: "warm",
                rotationPhrase: "rotates in 5d",
                lastCaller: "cli-test@\(name) 3m ago",
                llmTouched: false,
                tokenDies: "token dies in 55m"
            )
        }
        let cmd = SecretCommand(client: client, footerContextProvider: footerProvider)
        let getOut = try await cmd.run(subcommand: .get, args: ["OVH_APP_KEY"])
        // Re-seed since RecordingBrokerClient is consumed per call
        await client.seedPlaintext("OVH_APP_KEY", "aliasPlaintext")
        let fetchOut = try await cmd.run(subcommand: .fetch, args: ["OVH_APP_KEY"])
        #expect(fetchOut.stdout == getOut.stdout)
        #expect(fetchOut.stderr == getOut.stderr)
        // Both verbs must have hit the broker exactly once each
        let getCalls = await client.getCalls
        #expect(getCalls.count == 2)
    }

    @Test("get routes through BrokerClient.get and writes footer to stderr")
    func test_cli_secret_get_plumbsClientAndRendersFooter() async throws {
        let client = RecordingBrokerClient()
        await client.seedPlaintext("OVH_APP_KEY", "superSecretPlaintext")
        let cmd = SecretCommand(client: client) { name in
            InlineFooterContext(
                variant: .normalWarm,
                age: "4d",
                tier: "warm",
                rotationPhrase: "rotates in 3d",
                lastCaller: "cli-test@\(name) 1m ago",
                llmTouched: false,
                tokenDies: "token dies in 58m"
            )
        }
        let out = try await cmd.run(subcommand: .get, args: ["OVH_APP_KEY"])
        #expect(out.stdout.contains("superSecretPlaintext"))
        #expect(out.stderr.contains("# age 4d · warm"))
        #expect(out.stderr.contains("dies in"))
        #expect(!out.stderr.contains("expires_at"))
        let calls = await client.getCalls
        #expect(calls.count == 1)
        #expect(calls.first?.name == "OVH_APP_KEY")
    }

    @Test("list delegates to BrokerClient.list")
    func test_cli_secret_list_plumbsClient() async throws {
        let client = RecordingBrokerClient()
        await client.seedListings([
            VaultEntryRef(name: "A", scope: "ovh/*", tier: .warm, usageState: .warm,
                          lastRotated: Date(timeIntervalSince1970: 0),
                          rotationDue: Date(timeIntervalSince1970: 3600)),
        ])
        let cmd = SecretCommand(client: client) { _ in nil }
        let out = try await cmd.run(subcommand: .list, args: [])
        #expect(out.stdout.contains("A\tovh/*\twarm\twarm"))
    }

    @Test("set delegates to BrokerClient.set with name + value")
    func test_cli_secret_set_plumbsClient() async throws {
        let client = RecordingBrokerClient()
        let cmd = SecretCommand(client: client) { _ in nil }
        _ = try await cmd.run(subcommand: .set, args: ["NAME", "VAL"])
        let setCalls = await client.setCalls
        #expect(setCalls.count == 1)
        #expect(setCalls.first?.name == "NAME")
        #expect(setCalls.first?.value == "VAL")
    }

    @Test("rotate delegates to BrokerClient.rotate")
    func test_cli_secret_rotate_plumbsClient() async throws {
        let client = RecordingBrokerClient()
        await client.setNextRotationResult(RotationResult(secretName: "X", oldJtiSuffix: "abcd", invalidAt: Date(timeIntervalSince1970: 0)))
        let cmd = SecretCommand(client: client) { _ in nil }
        _ = try await cmd.run(subcommand: .rotate, args: ["X"])
        let calls = await client.rotateCalls
        #expect(calls.first?.name == "X")
    }

    @Test("revoke delegates to BrokerClient.revoke with jti")
    func test_cli_secret_revoke_plumbsClient() async throws {
        let client = RecordingBrokerClient()
        let cmd = SecretCommand(client: client) { _ in nil }
        _ = try await cmd.run(subcommand: .revoke, args: ["01JC0ABC0000000000000000K7"])
        let calls = await client.revokeCalls
        #expect(calls.first?.jti == "01JC0ABC0000000000000000K7")
    }

    @Test("missing arg throws")
    func test_cli_secret_get_missingArg_throws() async {
        let client = RecordingBrokerClient()
        let cmd = SecretCommand(client: client) { _ in nil }
        do {
            _ = try await cmd.run(subcommand: .get, args: [])
            Issue.record("expected missingArgument throw")
        } catch SecretCommandError.missingArgument(let which) {
            #expect(which == "name")
        } catch {
            Issue.record("wrong error: \(error)")
        }
    }
}
