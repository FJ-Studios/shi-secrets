import Foundation
import ShiSecretsKit

// MCPBridge — bearer-token validation + transport tagging for requests
// that arrive over the MCP channel (BR-D-03, BR-D-04, BR-D-05).
//
// The bridge itself is transport-agnostic: whoever plumbs stdin/stdout
// JSON-RPC messages (ShikkiMCP's executable) hands every decoded
// request envelope to the bridge, which:
//   1. validates the bearer against the pinned allowlist
//   2. wraps the request with `transport = .mcp` + `llmTouched = true`
//   3. returns a typed WrappedRequest the BrokerDaemon can forward
//
// Unix-socket requests bypass the bridge, defaulting `llmTouched = false`
// unless the caller uid is in the known LLM-bridge-uid set. That gate
// exists so a dev-shell invocation from a shi-mcp-bridge process still
// gets tagged as LLM-touched (BR-D-05).

public struct WrappedRequest: Sendable, Equatable {
    public let peerUid: UInt32?
    public let transport: AuditRow.Transport
    public let llmTouched: Bool
    /// Raw payload decoded by the caller — the bridge never peeks.
    public let payload: Data

    public init(
        peerUid: UInt32?,
        transport: AuditRow.Transport,
        llmTouched: Bool,
        payload: Data
    ) {
        self.peerUid = peerUid
        self.transport = transport
        self.llmTouched = llmTouched
        self.payload = payload
    }
}

public enum MCPBridgeError: Swift.Error, Sendable, Equatable {
    case bearerMissing
    case bearerRejected
}

/// MCPBridge — actor so the pinned bearer set + llm-bridge-uid set can be
/// mutated atomically without racing with incoming request tagging.
public actor MCPBridge {

    private var bearerAllowlist: Set<String>
    private var llmBridgeUids: Set<UInt32>

    public init(
        bearerAllowlist: Set<String> = [],
        llmBridgeUids: Set<UInt32> = []
    ) {
        self.bearerAllowlist = bearerAllowlist
        self.llmBridgeUids = llmBridgeUids
    }

    public func registerBearer(_ token: String) {
        bearerAllowlist.insert(token)
    }

    public func registerLLMBridgeUid(_ uid: UInt32) {
        llmBridgeUids.insert(uid)
    }

    /// BR-D-03 — validate a bearer token. Returns normally on hit; throws
    /// on miss/empty.
    public func validateBearer(_ bearer: String?) throws {
        guard let bearer, !bearer.isEmpty else {
            throw MCPBridgeError.bearerMissing
        }
        guard bearerAllowlist.contains(bearer) else {
            throw MCPBridgeError.bearerRejected
        }
    }

    /// Wraps an MCP request with `transport=.mcp` + `llmTouched=true`.
    /// BR-D-04: llm_touched is set server-side from transport type, never
    /// from the caller's payload.
    public func wrapMcpRequest(payload: Data, bearer: String?) throws -> WrappedRequest {
        try validateBearer(bearer)
        return WrappedRequest(
            peerUid: nil,
            transport: .mcp,
            llmTouched: true,
            payload: payload
        )
    }

    /// Wraps a unix-socket request. `llmTouched` defaults to false unless
    /// the kernel-reported uid appears in the registered LLM-bridge-uid set
    /// (BR-D-05 — known bridges get promoted).
    public func wrapUnixRequest(payload: Data, peerUid: UInt32) -> WrappedRequest {
        let isBridge = llmBridgeUids.contains(peerUid)
        return WrappedRequest(
            peerUid: peerUid,
            transport: .unix,
            llmTouched: isBridge,
            payload: payload
        )
    }

    /// Test accessor — bearer count. Used by BrokerDaemon preflight too
    /// so it can refuse to start with an empty allowlist in production.
    public var bearerCount: Int {
        bearerAllowlist.count
    }
}
