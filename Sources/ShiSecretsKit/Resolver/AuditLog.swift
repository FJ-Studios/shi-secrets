import Foundation

// AuditLog — fail-closed audit-log writer for ShiSecretResolver.
//
// BR-SSEC-09: every resolve/set/rotate call persists an audit entry to @db
// per [[db-is-truth-no-files-flying-on-computer]]. @db unreachable = FAIL
// CLOSED — never silently drop audit events. Resolver propagates the error
// rather than serving a value without an audit trail.
//
// W2 of features/shi-secrets-uri-scheme-and-plugin-extraction-2026-05-31.md.

/// A single audit event recorded against the broker.
public struct AuditEvent: Sendable, Equatable {
    /// Kind of operation being audited.
    public enum Kind: String, Sendable, Equatable, Codable {
        case resolved
        case setRequested = "set_requested"
        case rotated
        case ephemeralIssued = "ephemeral_issued"
        case rejected
        case cacheHit = "cache_hit"
    }

    public let kind: Kind
    public let uri: ShiSecretURI
    public let caller: String
    public let timestamp: Date
    public let note: String?

    public init(
        kind: Kind,
        uri: ShiSecretURI,
        caller: String,
        timestamp: Date,
        note: String? = nil
    ) {
        self.kind = kind
        self.uri = uri
        self.caller = caller
        self.timestamp = timestamp
        self.note = note
    }
}

/// Error thrown when the audit sink is unreachable.
///
/// `ShiSecretResolver` propagates this so callers fail-closed rather than
/// receiving a value without an audit trail.
public struct AuditLogUnreachableError: Error, LocalizedError, Sendable {
    public let underlying: String
    public init(underlying: String) {
        self.underlying = underlying
    }
    public var errorDescription: String? {
        "Audit log @db sink unreachable (\(underlying)); resolver fails closed per BR-SSEC-09."
    }
}

/// Sink for audit events. Concrete impls write to @db via shikki-db MCP;
/// tests inject an in-memory recorder.
public protocol AuditSink: Sendable {
    func record(_ event: AuditEvent) async throws
}

/// In-memory audit sink used by tests. Records events in-order; throws on
/// `record` only if `failNext` is set, exercising fail-closed behaviour.
public actor InMemoryAuditSink: AuditSink {
    public private(set) var events: [AuditEvent] = []
    private var failNext: Bool = false

    public init() {}

    public func record(_ event: AuditEvent) async throws {
        if failNext {
            failNext = false
            throw AuditLogUnreachableError(underlying: "test-injected failure")
        }
        events.append(event)
    }

    /// Test hook: cause the next `record(_:)` call to throw.
    public func setFailNext(_ shouldFail: Bool = true) {
        failNext = shouldFail
    }
}

/// Production audit sink that writes to @db via the shikki-db MCP server.
///
/// Wire-up note: the broker daemon process owns the MCP client and injects
/// a `SinkSendFn` closure that performs the actual `shi_save_event` call.
/// This struct stays pure-Swift so it can be unit-tested without a live MCP.
public struct ShikkiDBAuditSink: AuditSink, Sendable {
    public typealias SinkSendFn = @Sendable (AuditEvent) async throws -> Void

    private let send: SinkSendFn

    public init(send: @escaping SinkSendFn) {
        self.send = send
    }

    public func record(_ event: AuditEvent) async throws {
        try await send(event)
    }
}

/// Wraps an audit sink with a write-buffer that promotes underlying errors
/// into the canonical `AuditLogUnreachableError`. The resolver depends on
/// this exact error type to fail-closed.
public struct AuditLog: Sendable {
    private let sink: AuditSink

    public init(sink: AuditSink) {
        self.sink = sink
    }

    public func record(_ event: AuditEvent) async throws {
        do {
            try await sink.record(event)
        } catch let err as AuditLogUnreachableError {
            throw err
        } catch {
            throw AuditLogUnreachableError(underlying: "\(error)")
        }
    }
}
