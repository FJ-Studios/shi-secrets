// SecretsRevokeCommand — `shi secrets revoke --all-bots [--dry-run] [--i-know-what-im-doing]`
//
// Atomic revocation of ALL bot tokens.
// BR-SSEC-08: REQUIRES --i-know-what-im-doing (high blast-radius).
// Dry-run shows affected tokens BEFORE execution.
// TP-SSEC-14: --dry-run lists affected tokens, no mutation.
// TP-SSEC-15: atomic revocation, audit logged.
//
// W3+W4 of features/shi-secrets-uri-scheme-and-plugin-extraction-2026-05-31.md.

import Foundation
import ShiSecretsKit

/// `shi secrets revoke --all-bots [--dry-run] [--i-know-what-im-doing] [--json]`
public struct SecretsRevokeCommand {

    public let allBots: Bool
    public let dryRun: Bool
    public let iKnowWhatImDoing: Bool
    public let json: Bool

    public init(allBots: Bool = false, dryRun: Bool = false, iKnowWhatImDoing: Bool = false, json: Bool = false) {
        self.allBots = allBots
        self.dryRun = dryRun
        self.iKnowWhatImDoing = iKnowWhatImDoing
        self.json = json
    }

    public func run(brokerSocket: String) async throws -> Int32 {
        guard allBots else {
            fputs("ERROR: currently only --all-bots revocation is supported.\n", stderr)
            return 1
        }

        let client = ShiSecretsAPIClient(socket: brokerSocket)

        if dryRun {
            // Dry-run: show affected tokens, no mutation.
            do {
                let affected = try await client.listActiveBotTokens()
                if json {
                    let tokens = "[" + affected.map { "\"\($0)\"" }.joined(separator: ",") + "]"
                    print("{\"dry_run\":true,\"would_revoke\":\(tokens),\"count\":\(affected.count)}")
                } else {
                    print("DRY RUN — would revoke \(affected.count) bot token(s):")
                    affected.forEach { print("  \($0)") }
                    print("Run without --dry-run and with --i-know-what-im-doing to execute.")
                }
                return 0
            } catch {
                fputs("ERROR: \(error.localizedDescription)\n", stderr)
                return 1
            }
        }

        // BR-SSEC-08: live revocation requires --i-know-what-im-doing.
        guard iKnowWhatImDoing else {
            fputs("ERROR: --all-bots revocation is HIGH blast-radius.\n", stderr)
            fputs("  Pass --i-know-what-im-doing to confirm.\n", stderr)
            fputs("  Use --dry-run first to preview affected tokens.\n", stderr)
            return 1
        }

        do {
            let count = try await client.revokeAllBotTokens()
            if json {
                print("{\"status\":\"revoked\",\"count\":\(count)}")
            } else {
                fputs("Revoked \(count) bot token(s) — audit logged.\n", stderr)
            }
            return 0
        } catch {
            fputs("ERROR: revocation failed: \(error.localizedDescription)\n", stderr)
            return 1
        }
    }
}
