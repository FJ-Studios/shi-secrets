// PluginRegistration — ShiSecretsPlugin: PluginCLISurface conformance.
//
// Registers `secrets` verb + 9 sub-verbs with shikki-cli at plugin install time.
// Also registers VaultUriDeprecatedCheck via PluginDoctorRegistrar.
//
// BR-SSEC-06: plugin conforms to PluginCLISurface from shikki-plugin-api v0.1.3+.
// §3.5 of features/shi-secrets-uri-scheme-and-plugin-extraction-2026-05-31.md.

import Foundation
import ShikkiPluginAPI

/// ShiSecretsPlugin — registers `shi secrets` verb and its 11 sub-verbs with shikki-cli.
public struct ShiSecretsPlugin: PluginCLISurface {

    public static let verb = "secrets"

    public static let subVerbs: [String] = [
        "list",
        "get",
        "set",
        "status",
        "secrets-to-env",
        "rotate",
        "blast-radius",
        "revoke",
        "audit",
        "brokerd",
        "setup",           // W3.1: `shi secrets setup vault-credentials` + `shi secrets setup install`
    ]

    /// Dispatch entry-point called by shikki-cli for `shi secrets <subVerb> [args...]`.
    public static func execute(subVerb: String, args: [String]) async throws -> Int32 {
        let socketPath = ProcessInfo.processInfo.environment["SHIKKI_BROKER_SOCKET"]
            ?? "\(NSHomeDirectory())/.shikki/run/secrets-brokerd.sock"

        switch subVerb {
        case "list":
            var ns: String? = nil
            var jsonFlag = false
            var i = 0
            while i < args.count {
                switch args[i] {
                case "--namespace":
                    i += 1; if i < args.count { ns = args[i] }
                case "--json":
                    jsonFlag = true
                default: break
                }
                i += 1
            }
            return try await SecretsListCommand(namespace: ns, json: jsonFlag).run(brokerSocket: socketPath)

        case "get":
            guard let uri = args.first else {
                fputs("Usage: shi secrets get <uri> [--ephemeral] [--value] [--json]\n", stderr)
                return 1
            }
            let ephemeral = args.contains("--ephemeral")
            let valueFlag = args.contains("--value")
            let jsonFlag = args.contains("--json")
            return try await SecretsGetCommand(uri: uri, ephemeral: ephemeral, value: valueFlag, json: jsonFlag)
                .run(brokerSocket: socketPath)

        case "set":
            guard let arg = args.first else {
                fputs("Usage: shi secrets set <uri>=<value> [--json]\n", stderr)
                return 1
            }
            let jsonFlag = args.contains("--json")
            return try await SecretsSetCommand(uriEqualsValue: arg, json: jsonFlag)
                .run(brokerSocket: socketPath)

        case "status":
            let jsonFlag = args.contains("--json")
            return try await SecretsStatusCommand(json: jsonFlag).run(brokerSocket: socketPath)

        case "secrets-to-env":
            // Parse: --secret KEY=<uri> [--secret KEY2=<uri2>] -- <cmd...>
            var secrets: [(envKey: String, uri: String)] = []
            var cmd: [String] = []
            var i = 0
            var pastSeparator = false
            while i < args.count {
                if pastSeparator {
                    cmd.append(args[i])
                } else if args[i] == "--" {
                    pastSeparator = true
                } else if args[i] == "--secret", i + 1 < args.count {
                    i += 1
                    let pair = args[i]
                    if let eqIdx = pair.firstIndex(of: "=") {
                        let k = String(pair[pair.startIndex..<eqIdx])
                        let v = String(pair[pair.index(after: eqIdx)...])
                        secrets.append((envKey: k, uri: v))
                    }
                }
                i += 1
            }
            return try await SecretsToEnvCommand(secrets: secrets, command: cmd)
                .run(brokerSocket: socketPath)

        case "rotate":
            guard let uri = args.first else {
                fputs("Usage: shi secrets rotate <uri> [--json]\n", stderr)
                return 1
            }
            let jsonFlag = args.contains("--json")
            return try await SecretsRotateCommand(uri: uri, json: jsonFlag).run(brokerSocket: socketPath)

        case "blast-radius":
            guard let token = args.first else {
                fputs("Usage: shi secrets blast-radius <token> [--json]\n", stderr)
                return 1
            }
            let jsonFlag = args.contains("--json")
            return try await SecretsBlastRadiusCommand(token: token, json: jsonFlag)
                .run(brokerSocket: socketPath)

        case "revoke":
            let allBots = args.contains("--all-bots")
            let dryRun = args.contains("--dry-run")
            let confirm = args.contains("--i-know-what-im-doing")
            let jsonFlag = args.contains("--json")
            return try await SecretsRevokeCommand(
                allBots: allBots, dryRun: dryRun, iKnowWhatImDoing: confirm, json: jsonFlag
            ).run(brokerSocket: socketPath)

        case "audit":
            var since: String? = nil
            var caller: String? = nil
            var namespace: String? = nil
            var jsonFlag = false
            var i = 0
            while i < args.count {
                switch args[i] {
                case "--since": i += 1; if i < args.count { since = args[i] }
                case "--caller": i += 1; if i < args.count { caller = args[i] }
                case "--namespace": i += 1; if i < args.count { namespace = args[i] }
                case "--json": jsonFlag = true
                default: break
                }
                i += 1
            }
            return try await SecretsAuditCommand(since: since, caller: caller, namespace: namespace, json: jsonFlag)
                .run(brokerSocket: socketPath)

        case "brokerd":
            // Bug 3 fix: `shi secrets brokerd start` must NEVER call `swift build`.
            // The pre-built binary ships via `shi pickup shi-secrets` into
            // ~/.shikki/bin/shikki-secrets-brokerd. If it exists, use launchctl
            // to load the plist. If missing, surface a clear reinstall hint.
            guard let action = args.first else {
                fputs("Usage: shi secrets brokerd <start|stop|status>\n", stderr)
                return 1
            }
            return try await SecretsBrokerdCommand(action: action).run()

        case "setup":
            // `shi secrets setup vault-credentials [flags]` — W3.1
            // `shi secrets setup install` — install launchd plist (referenced in error messages)
            guard let subAction = args.first else {
                fputs("Usage: shi secrets setup <vault-credentials|install> [flags]\n", stderr)
                return 1
            }
            switch subAction {
            case "vault-credentials":
                return await runSetupVaultCredentials(args: Array(args.dropFirst()))
            case "install":
                // TODO W4: install the launchd plist. For now, surface a clear message.
                fputs(
                    """
                    shi secrets setup install: not yet implemented in this binary.
                    Run the install script manually or use `shi pickup shi-secrets`.
                    """,
                    stderr
                )
                return 1
            default:
                fputs("Unknown setup sub-action: \(subAction). Try: vault-credentials, install\n", stderr)
                return 1
            }

        default:
            fputs("Unknown secrets sub-verb: \(subVerb). Try: \(subVerbs.joined(separator: ", "))\n", stderr)
            return 1
        }
    }

    // MARK: - setup vault-credentials helper

    private static func runSetupVaultCredentials(args: [String]) async -> Int32 {
        // Parse flags manually (no ArgumentParser dep in ShiSecrets target).
        var clientID: String? = nil
        var serverURL: String? = nil
        var clientSecretArg: String? = nil
        var force = false
        var noVerify = false

        var i = 0
        while i < args.count {
            switch args[i] {
            case "--client-id":
                i += 1; if i < args.count { clientID = args[i] }
            case "--server-url":
                i += 1; if i < args.count { serverURL = args[i] }
            case "--client-secret":
                i += 1; if i < args.count { clientSecretArg = args[i] }
            case "--force":
                force = true
            case "--no-verify":
                noVerify = true
            case "--help", "-h":
                printSetupVaultCredentialsHelp()
                return 0
            default:
                fputs("Unknown flag: \(args[i])\n", stderr)
                printSetupVaultCredentialsHelp()
                return 1
            }
            i += 1
        }

        guard let resolvedClientID = clientID, !resolvedClientID.isEmpty else {
            fputs("ERROR: --client-id is required.\n", stderr)
            printSetupVaultCredentialsHelp()
            return 1
        }
        guard let resolvedServerURL = serverURL, !resolvedServerURL.isEmpty else {
            fputs("ERROR: --server-url is required.\n", stderr)
            printSetupVaultCredentialsHelp()
            return 1
        }

        let cmd = SecretsSetupVaultCredentialsCommand(
            clientID: resolvedClientID,
            serverURL: resolvedServerURL,
            clientSecretArg: clientSecretArg,
            force: force,
            noVerify: noVerify
        )
        return await cmd.run()
    }

    private static func printSetupVaultCredentialsHelp() {
        fputs(
            """
            OVERVIEW: Seed Vaultwarden OAuth credentials (client_id, client_secret, server_url)
            into the macOS Keychain. First-time setup, after Keychain wipe, or after
            Bitwarden API key rotation.

            Get client_id + client_secret from your Bitwarden account at
            Settings → Security → Keys → API Key.

            USAGE: shi secrets setup vault-credentials --client-id <id> --server-url <url> [flags]

            FLAGS:
              --client-id <user.UUID>      Required. Bitwarden client_id (must start with "user.").
              --server-url <https://...>   Required. Vaultwarden server URL.
              --client-secret <secret>     Optional. Prompted with no-echo if omitted.
                                           Pass "-" to read a single line from stdin.
              --force                      Overwrite an existing Keychain entry.
              --no-verify                  Skip the OAuth round-trip verification.
              --help                       Show this help.

            """,
            stderr
        )
    }
}
