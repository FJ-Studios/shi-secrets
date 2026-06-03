// SecretsRotateCommand — `shi secrets rotate <uri>`
//
// Triggers backend rotation + invalidates in-process cache.
// TP-SSEC-12: backend rotation, cache invalidated, audit logged.
//
// W3+W4 of features/shi-secrets-uri-scheme-and-plugin-extraction-2026-05-31.md.

import Foundation
import ShiSecretsKit

/// `shi secrets rotate <uri> [--json]`
public struct SecretsRotateCommand {

    public let uri: String
    public let json: Bool

    public init(uri: String, json: Bool = false) {
        self.uri = uri
        self.json = json
    }

    public func run(brokerSocket: String) async throws -> Int32 {
        let parsedURI: ShiSecretURI
        do {
            parsedURI = try ShiSecretURI.parse(uri)
        } catch {
            fputs("ERROR: \(error.localizedDescription)\n", stderr)
            return 1
        }

        let client = ShiSecretsAPIClient(socket: brokerSocket)
        do {
            try await client.rotate(uri: parsedURI)
            if json {
                print("{\"uri\":\"\(uri)\",\"status\":\"rotated\"}")
            } else {
                fputs("Rotated \(uri) — cache invalidated.\n", stderr)
            }
            return 0
        } catch {
            fputs("ERROR: rotation failed: \(error.localizedDescription)\n", stderr)
            return 1
        }
    }
}
