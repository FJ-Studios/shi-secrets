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
    /// CRIT-2: the UID that owns this broker instance. Mutations (set/list/delete)
    /// are only permitted when peerUid == ownerUid.
    private let ownerUid: UInt32

    public init(daemon: BrokerDaemon, bridge: MCPBridge, ownerUid: UInt32 = UInt32(getuid())) {
        self.daemon = daemon
        self.bridge = bridge
        self.ownerUid = ownerUid
    }

    /// Decode a `WireRequest` and route it to the matching handler. The
    /// `peerUid` is captured from `SO_PEERCRED` at accept(2) time
    /// and carried into the audit row and auth check.
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
        // Bug 1 fix: accept BOTH wire shapes for backward-compatibility.
        //
        // Shape A (canonical broker form):
        //   { sub: String, scope: String, op: "read"|"rotate", ttl: Int, toolName?: String }
        //
        // Shape B (client shorthand — ProductionBrokerClient.get(name:) sends this):
        //   { name: String }
        //
        // When Shape B is received, translate to Shape A using defaults:
        //   sub   = current process username ($USER env or NSUserName())
        //   scope = <name>   (the secret name IS the scope path)
        //   op    = "read"
        //   ttl   = 300
        let params: SecretGetParams
        do {
            // Try Shape A first (full canonical params).
            if let canonical = try? decodeParams(SecretGetParams.self, from: request.params) {
                params = canonical
            } else {
                // Try Shape B: { name: String } — translate to canonical form.
                struct NameOnlyParams: Decodable { let name: String }
                let nameParams = try decodeParams(NameOnlyParams.self, from: request.params)
                // Map name → scope (the secret name IS the scope path in the broker model).
                params = SecretGetParams(
                    sub: ProcessInfo.processInfo.environment["USER"] ?? NSUserName(),
                    scope: nameParams.name,
                    op: .read,
                    ttl: 300,
                    toolName: nil,
                    name: nameParams.name
                )
            }
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

        // W4.2 — local-unix callers receive .boundPlaintext. The existing
        // ProductionBrokerClient.get() expects result: .string(value) (not
        // an object envelope). Emit the plaintext directly so the client
        // decode path succeeds without cross-repo changes.
        //
        // All other response cases use the standard toWireResponse() encoder.
        if case let .boundPlaintext(_, plaintext) = response {
            return WireResponse(id: request.id, result: .string(plaintext))
        }

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

    // MARK: - Auth gate (CRIT-2)

    /// Returns an authorization-denied WireResponse when peerUid ≠ ownerUid,
    /// also emitting an audit row for the rejected attempt.
    private func requireOwner(_ request: WireRequest, peerUid: UInt32) async -> WireResponse? {
        guard peerUid == ownerUid else {
            // Emit audit row for rejected mutation attempt (deny, no reason = write op rejection).
            _ = try? await daemon.audit.append(.init(
                ts: Date(),
                tokenJti: "wire-\(request.method)-denied",
                callerUid: Int32(bitPattern: peerUid),
                callerTransport: .unix,
                secretName: "(wire:\(request.method))",
                op: .read,
                allow: .deny,
                reason: .scopePatternDenied,
                llmTouched: false
            ))
            return WireResponse(id: request.id, error: WireError(
                code: WireErrorCode.denied,
                message: "Unauthorized: peerUid \(peerUid) != ownerUid \(ownerUid)"
            ))
        }
        return nil
    }

    // MARK: - secret.set (W3 — wired to BWClient.set)

    private func dispatchSecretSet(_ request: WireRequest, peerUid: UInt32) async -> WireResponse {
        // CRIT-2: gate on owner identity before any mutation.
        if let denied = await requireOwner(request, peerUid: peerUid) { return denied }

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
            // CRIT-2: audit every mutation.
            _ = try? await daemon.audit.append(.init(
                ts: Date(),
                tokenJti: "wire-set-\(UUID().uuidString.prefix(8))",
                callerUid: Int32(bitPattern: peerUid),
                callerTransport: .unix,
                secretName: String(params.name.prefix(AuditWriter.maxSecretNameLength)),
                op: .rotate,
                allow: .allow,
                reason: nil,
                llmTouched: false
            ))
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
        // CRIT-2: gate on owner identity — listing is a read op but exposes all names.
        if let denied = await requireOwner(request, peerUid: peerUid) { return denied }

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
            // Bug 2 fix: return [VaultEntryRef] shaped objects instead of raw
            // [String] names. ProductionBrokerClient.list() decodes [VaultEntryRef]
            // — returning bare strings causes DecodingError.typeMismatch.
            //
            // Synthetic defaults for metadata fields not yet tracked by BWClient.list():
            //   scope        = "default"
            //   tier         = .warm
            //   usageState   = .warm
            //   lastRotated  = epoch (unknown — broker does not store rotation history yet)
            //   rotationDue  = +7 days (warm tier baseline)
            let now = Date()
            let sevenDaysFromNow = now.addingTimeInterval(7 * 24 * 3600)
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            let items: [JSONValue] = try filtered.map { name in
                let ref = VaultEntryRef(
                    name: name,
                    scope: "default",
                    tier: .warm,
                    usageState: .warm,
                    lastRotated: Date(timeIntervalSince1970: 0),
                    rotationDue: sevenDaysFromNow
                )
                let data = try encoder.encode(ref)
                return try JSONDecoder().decode(JSONValue.self, from: data)
            }
            // CRIT-2: audit list access.
            _ = try? await daemon.audit.append(.init(
                ts: Date(),
                tokenJti: "wire-list-\(UUID().uuidString.prefix(8))",
                callerUid: Int32(bitPattern: peerUid),
                callerTransport: .unix,
                secretName: "(list)",
                op: .read,
                allow: .allow,
                reason: nil,
                llmTouched: false
            ))
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
        // CRIT-2: gate on owner identity before any mutation.
        if let denied = await requireOwner(request, peerUid: peerUid) { return denied }

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
            // CRIT-2: audit every mutation.
            _ = try? await daemon.audit.append(.init(
                ts: Date(),
                tokenJti: "wire-delete-\(UUID().uuidString.prefix(8))",
                callerUid: Int32(bitPattern: peerUid),
                callerTransport: .unix,
                secretName: String(params.name.prefix(AuditWriter.maxSecretNameLength)),
                op: .rotate,
                allow: .allow,
                reason: nil,
                llmTouched: false
            ))
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
    ///
    /// Bug 1 fix: `name` is the shorthand field emitted by
    /// `ProductionBrokerClient.get(name:)` — `{name: "x"}`. When present
    /// and the canonical fields (`sub`, `scope`, `op`, `ttl`) are absent, the
    /// dispatcher fills in safe defaults (see `dispatchSecretGet`).
    private struct SecretGetParams: Decodable {
        let sub: String
        let scope: String
        let op: ShikkiSBT.Op
        let ttl: Int
        let toolName: String?
        /// Shorthand name field (Shape B — client shorthand form).
        let name: String?

        init(sub: String, scope: String, op: ShikkiSBT.Op, ttl: Int, toolName: String?, name: String? = nil) {
            self.sub = sub
            self.scope = scope
            self.op = op
            self.ttl = ttl
            self.toolName = toolName
            self.name = name
        }
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
