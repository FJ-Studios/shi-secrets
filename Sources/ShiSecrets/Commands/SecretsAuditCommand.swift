// SecretsAuditCommand — `shi secrets audit [--since <date>] [--caller <id>] [--namespace <ns>]`
//
// Queries the @db-backed audit log.
// TP-SSEC-16: queryable by --since/--caller/--namespace; @db-backed.
//
// W3+W4 of features/shi-secrets-uri-scheme-and-plugin-extraction-2026-05-31.md.

import Foundation
import ShiSecretsKit

/// `shi secrets audit [--since <iso-date>] [--caller <id>] [--namespace <ns>] [--json]`
public struct SecretsAuditCommand {

    public let since: String?
    public let caller: String?
    public let namespace: String?
    public let json: Bool

    public init(since: String? = nil, caller: String? = nil, namespace: String? = nil, json: Bool = false) {
        self.since = since
        self.caller = caller
        self.namespace = namespace
        self.json = json
    }

    public func run(brokerSocket: String) async throws -> Int32 {
        // Validate --since as ISO 8601 date if provided.
        var sinceDate: Date?
        if let sinceStr = since {
            let fmt = ISO8601DateFormatter()
            fmt.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            let fmt2 = ISO8601DateFormatter()
            fmt2.formatOptions = [.withInternetDateTime]
            if let d = fmt.date(from: sinceStr) ?? fmt2.date(from: sinceStr) {
                sinceDate = d
            } else {
                fputs("ERROR: --since value '\(sinceStr)' is not a valid ISO 8601 date.\n", stderr)
                return 1
            }
        }

        let client = ShiSecretsAPIClient(socket: brokerSocket)
        do {
            let entries = try await client.queryAuditLog(since: sinceDate, caller: caller, namespace: namespace)
            if json {
                // Emit each entry as a JSON object, newline-separated.
                if entries.isEmpty {
                    print("[]")
                } else {
                    let rows = entries.map { e in
                        "{\"timestamp\":\"\(e.timestamp)\",\"kind\":\"\(e.kind)\",\"uri\":\"\(e.uri)\",\"caller\":\"\(e.caller)\"}"
                    }
                    print("[" + rows.joined(separator: ",\n ") + "]")
                }
            } else {
                if entries.isEmpty {
                    fputs("(no audit entries match the filter)\n", stderr)
                } else {
                    entries.forEach { e in
                        print("\(e.timestamp)\t\(e.kind)\t\(e.uri)\t\(e.caller)")
                    }
                }
            }
            return 0
        } catch {
            fputs("ERROR: \(error.localizedDescription)\n", stderr)
            return 1
        }
    }
}

