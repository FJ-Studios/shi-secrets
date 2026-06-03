// SecretsStatusCommand — `shi secrets status [--json]`
//
// Reports broker daemon health + backend reachability + ACL state.
// TP-SSEC-10: reports daemon health + backend reachability.
//
// W3+W4 of features/shi-secrets-uri-scheme-and-plugin-extraction-2026-05-31.md.

import Foundation
import ShiSecretsKit

/// `shi secrets status [--json]`
public struct SecretsStatusCommand {

    public let json: Bool

    public init(json: Bool = false) {
        self.json = json
    }

    public func run(brokerSocket: String) async throws -> Int32 {
        let client = ShiSecretsAPIClient(socket: brokerSocket)
        let socketReachable = await client.ping()
        let backendReachable = socketReachable ? (await client.backendHealthCheck()) : false

        if json {
            let status = """
            {
              "broker_socket": "\(brokerSocket)",
              "broker_reachable": \(socketReachable),
              "backend_reachable": \(backendReachable)
            }
            """
            print(status)
        } else {
            print("Broker socket : \(brokerSocket)")
            print("Broker        : \(socketReachable ? "reachable" : "UNREACHABLE")")
            print("Backend       : \(backendReachable ? "reachable" : "UNREACHABLE")")
            if !socketReachable {
                fputs("Run `shi secrets setup install` + `shi secrets brokerd start` to start the daemon.\n", stderr)
            }
        }
        return socketReachable ? 0 : 1
    }
}
