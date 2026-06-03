import Foundation
import ShiSecretsKit

// BrokerWireDispatch — routes JSON-RPC `WireRequest` frames to the
// corresponding `BrokerDaemon` handler.
//
// Phase 0.3c (BR-G-04 decoder half) of features/shikkisecrets-broker-completion.md.
//
// Wire shape:
//   WireRequest (NDJSON) → method-named arm → BrokerRequest →
//     BrokerDaemon.handleRequest → BrokerResponse → toWireResponse(id:)
//
// W3 (2026-05-26): secret.{set,list,delete} wired to BWClient.{set,list,delete}.
// The W3 write path uses Vaultwarden's API-key plaintext path (no client-side
// encryption — see decision @db shikki.secrets.W3-encryption-decision).
//
// Lives in ShiSecretsBrokerd because it needs `BrokerDaemon` +
// `MCPBridge` types that are private to the daemon target.

public actor BrokerWireDispatcher {

    private let daemon: BrokerDaemon
    private let bridge: MCPBridge

    public init(daemon: BrokerDaemon, bridge: MCPBridge) {
        self.daemon = daemon
        self.bridge = bridge
    }

    /// Decode a `WireRequest` and route it to the matching handler. The
    /// `peerUid` is captured from `SO_PEERCRED` at accept(2) time
    /// (Phase 0.1) and carried into the audit row.
    public func dispatch(_ request: WireRequest, peerUid: UInt32) async -> WireResponse {
        switch request.method {

        case "secret.get":
            return await dispatchSecretGet(request, peerUid: peerUid)

        case "secret.set":
            return await dispatchSecretSet(request, peerUid: peerUid)

        case "secret.list":
            return await dispatchSecretList(request, peerUid: peerUid)

        case "secret.delete":
            return await dispatchSecretDelete(request, peerUid: peerUid)

        // Phase 0.5+: token.{revoke, revokeAllBots, revokeAllBotsSigned}.
        // Phase 0.6+: audit.{blastRadius, recent, seams}.
        default:
            return WireResponse.methodNotFound(id: request.id, method: request.method)
        }
    }

    private func dispatchSecretGet(_ request: WireRequest, peerUid: UInt32) async -> WireResponse {
        // Decode params into a BrokerRequest. The wire shape:
        //   { sub: String, scope: String, op: "read"|"rotate", ttl: Int, toolName?: String }
        let params: SecretGetParams
        do {
            params = try decodeParams(SecretGetParams.self, from: request.params)
        } catch {
            return WireResponse(
                id: request.id,
                error: WireError(
                    code: WireErrorCode.invalidParams,
                    message: "Invalid params for secret.get: \(error)"
                )
            )
        }

        let brokerRequest = BrokerRequest(
            sub: params.sub,
            scope: params.scope,
            op: params.op,
            ttl: params.ttl,
            toolName: params.toolName
        )

        // Build the WrappedRequest with the original JSON payload so audit
        // rows preserve the raw caller bytes.
        let payload = (try? JSONEncoder().encode(request)) ?? Data()
        let wrapped = await bridge.wrapUnixRequest(payload: payload, peerUid: peerUid)

        let response = await daemon.handleRequest(brokerRequest, wrapped: wrapped)
        do {
            return try response.toWireResponse(id: request.id)
        } catch {
            return WireResponse(
                id: request.id,
                error: WireError(
                    code: WireErrorCode.internalError,
                    message: "Failed to encode broker response: \(error)"
                )
            )
        }
    }

    // MARK: - secret.set (W3 — wired to BWClient.set)

    private func dispatchSecretSet(_ request: WireRequest, peerUid: UInt32) async -> WireResponse {
        struct SetParams: Decodable {
            let name: String
            let value: String
        }
        let params: SetParams
        do {
            params = try decodeParams(SetParams.self, from: request.params)
        } catch {
            return WireResponse(id: request.id, error: WireError(
                code: WireErrorCode.invalidParams,
                message: "Invalid params for secret.set: \(error)"
            ))
        }
        do {
            try await daemon.bwClient.set(name: params.name, value: params.value)
            return WireResponse(id: request.id, result: .object(["ok": .bool(true)]))
        } catch {
            return WireResponse(id: request.id, error: WireError(
                code: WireErrorCode.internalError,
                message: "secret.set failed: \(error)"
            ))
        }
    }

    // MARK: - secret.list (W3 — wired to BWClient.list)

    private func dispatchSecretList(_ request: WireRequest, peerUid: UInt32) async -> WireResponse {
        struct ListParams: Decodable {
            let filter: String?
        }
        // params is optional for list — default to no filter.
        let filter: String?
        if let p = request.params {
            filter = (try? decodeParams(ListParams.self, from: p))?.filter
        } else {
            filter = nil
        }
        do {
            let names = try await daemon.bwClient.list()
            // Apply optional prefix glob filter (v1: prefix match).
            let filtered: [String]
            if let f = filter, !f.isEmpty {
                let prefix = f.hasSuffix("*") ? String(f.dropLast()) : f
                filtered = names.filter { $0.hasPrefix(prefix) }
            } else {
                filtered = names
            }
            let items = filtered.map { JSONValue.string($0) }
            return WireResponse(id: request.id, result: .array(items))
        } catch {
            return WireResponse(id: request.id, error: WireError(
                code: WireErrorCode.internalError,
                message: "secret.list failed: \(error)"
            ))
        }
    }

    // MARK: - secret.delete (W3 — wired to BWClient.delete)

    private func dispatchSecretDelete(_ request: WireRequest, peerUid: UInt32) async -> WireResponse {
        struct DeleteParams: Decodable {
            let name: String
        }
        let params: DeleteParams
        do {
            params = try decodeParams(DeleteParams.self, from: request.params)
        } catch {
            return WireResponse(id: request.id, error: WireError(
                code: WireErrorCode.invalidParams,
                message: "Invalid params for secret.delete: \(error)"
            ))
        }
        do {
            try await daemon.bwClient.delete(name: params.name)
            return WireResponse(id: request.id, result: .object(["ok": .bool(true)]))
        } catch {
            return WireResponse(id: request.id, error: WireError(
                code: WireErrorCode.internalError,
                message: "secret.delete failed: \(error)"
            ))
        }
    }

    // MARK: - Params

    /// Decoded params for `secret.get`.
    private struct SecretGetParams: Decodable {
        let sub: String
        let scope: String
        let op: ShikkiSBT.Op
        let ttl: Int
        let toolName: String?
    }

    /// Decode a typed params struct from a JSONValue tree by re-encoding
    /// through JSON. Avoids ad-hoc per-method JSON walking.
    private func decodeParams<T: Decodable>(_ type: T.Type, from value: JSONValue?) throws -> T {
        guard let value else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(codingPath: [], debugDescription: "params required")
            )
        }
        let data = try JSONEncoder().encode(value)
        return try JSONDecoder().decode(T.self, from: data)
    }
}
