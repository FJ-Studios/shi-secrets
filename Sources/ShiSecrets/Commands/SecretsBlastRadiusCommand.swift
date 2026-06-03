// SecretsBlastRadiusCommand — `shi secrets blast-radius <token>`
//
// Per-bot blast-radius simulator. Returns: granted namespaces, callable verbs,
// time-bound expiry, last 10 audit entries.
// BR-SSEC-14: per-bot blast-radius simulator.
// TP-SSEC-13: returns namespaces + verbs + expiry + audit summary.
//
// W3+W4 of features/shi-secrets-uri-scheme-and-plugin-extraction-2026-05-31.md.

import Foundation
import ShiSecretsKit

/// `shi secrets blast-radius <token> [--json]`
public struct SecretsBlastRadiusCommand {

    public let token: String
    public let json: Bool

    public init(token: String, json: Bool = false) {
        self.token = token
        self.json = json
    }

    public func run(brokerSocket: String) async throws -> Int32 {
        let client = ShiSecretsAPIClient(socket: brokerSocket)
        do {
            let report = try await client.blastRadius(token: token)
            if json {
                let namespaces = "[" + report.namespaces.map { "\"\($0)\"" }.joined(separator: ",") + "]"
                let verbs = "[" + report.verbs.map { "\"\($0)\"" }.joined(separator: ",") + "]"
                let auditEntries = "[" + report.lastAuditEntries.map { "\"\($0)\"" }.joined(separator: ",") + "]"
                print("{\"namespaces\":\(namespaces),\"verbs\":\(verbs),\"expires_at\":\"\(report.expiresAt)\",\"last_audit\":\(auditEntries)}")
            } else {
                print("Token       : \(token.prefix(8))…")
                print("Namespaces  : \(report.namespaces.joined(separator: ", "))")
                print("Verbs       : \(report.verbs.joined(separator: ", "))")
                print("Expires at  : \(report.expiresAt)")
                print("Last audit  :")
                report.lastAuditEntries.forEach { print("  \($0)") }
            }
            return 0
        } catch {
            fputs("ERROR: \(error.localizedDescription)\n", stderr)
            return 1
        }
    }
}

