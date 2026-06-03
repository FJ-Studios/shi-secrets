import Foundation

// ShiSecretResolver — 6-step pipeline that resolves `shi-secret://` URIs
// into ephemeral `SecretValue`s by mediating between caller, ACL, broker,
// backend, and audit log.
//
// BR-SSEC-02: pipeline is cache → ACL → broker → backend → audit → cache.
// Each step is observable + injectable so the resolver can be unit-tested
// without a live broker daemon.
//
// W2 of features/shi-secrets-uri-scheme-and-plugin-extraction-2026-05-31.md.

/// Per-caller identity used by ACL decisions.
public struct PeerCredential: Sendable, Equatable, Hashable {
    public let id: String
    public init(id: String) { self.id = id }
}

/// ACL decision for a (caller, namespace) pair.
public protocol ACLProvider: Sendable {
    func check(caller: PeerCredential, namespace: String) async throws
}

/// Broker contract — returns an ephemeral token bound to the URI.
public protocol ShiSecretBroker: Sendable {
    func requestEphemeralToken(for uri: ShiSecretURI, caller: PeerCredential) async throws -> EphemeralToken
}

/// Backend contract — exchanges an ephemeral token for the plaintext value.
public protocol SecretsBackend: Sendable {
    func resolve(token: EphemeralToken, qualifiedKey: String) async throws -> InMemoryCache.SecretValue
}

/// Token returned by the broker, scoped to a single resolve call.
public struct EphemeralToken: Sendable, Equatable {
    public let value: String
    public let expiresAt: Date
    public init(value: String, expiresAt: Date) {
        self.value = value
        self.expiresAt = expiresAt
    }
}

/// Permanent error returned when the caller is not allowed to access the namespace.
public struct ACLDeniedError: Error, LocalizedError, Sendable, Equatable {
    public let caller: String
    public let namespace: String
    public init(caller: String, namespace: String) {
        self.caller = caller
        self.namespace = namespace
    }
    public var errorDescription: String? {
        "ACL denied: caller '\(caller)' may not access namespace '\(namespace)'."
    }
}

/// The 6-step resolver actor.
///
/// Pipeline (BR-SSEC-02):
///  1. cache lookup — return cached value if non-expired
///  2. ACL check — caller allowed in namespace
///  3. broker — request ephemeral token
///  4. backend — exchange token for value
///  5. audit — record the resolve event (FAIL CLOSED if @db unreachable)
///  6. cache set — store for TTL
public actor ShiSecretResolver {
    private let cache: InMemoryCache
    private let acl: ACLProvider
    private let broker: ShiSecretBroker
    private let backend: SecretsBackend
    private let auditLog: AuditLog
    private let clock: @Sendable () -> Date

    public init(
        cache: InMemoryCache,
        acl: ACLProvider,
        broker: ShiSecretBroker,
        backend: SecretsBackend,
        auditLog: AuditLog,
        clock: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.cache = cache
        self.acl = acl
        self.broker = broker
        self.backend = backend
        self.auditLog = auditLog
        self.clock = clock
    }

    /// Resolve `uri` for the given `caller`. Returns an ephemeral `SecretValue`.
    public func resolve(uri: ShiSecretURI, caller: PeerCredential) async throws -> InMemoryCache.SecretValue {
        // 1. Cache lookup.
        if let cached = await cache.get(uri) {
            try await auditLog.record(.init(
                kind: .cacheHit,
                uri: uri,
                caller: caller.id,
                timestamp: clock()
            ))
            return cached
        }

        // 2. ACL.
        do {
            try await acl.check(caller: caller, namespace: uri.namespace)
        } catch {
            // Audit the rejection (fail-closed propagates if audit also fails).
            try await auditLog.record(.init(
                kind: .rejected,
                uri: uri,
                caller: caller.id,
                timestamp: clock(),
                note: "ACL denied"
            ))
            throw ACLDeniedError(caller: caller.id, namespace: uri.namespace)
        }

        // 3. Broker.
        let token = try await broker.requestEphemeralToken(for: uri, caller: caller)

        // 4. Backend.
        let value = try await backend.resolve(token: token, qualifiedKey: uri.qualifiedKey)

        // 5. Audit (fail-closed per BR-SSEC-09).
        try await auditLog.record(.init(
            kind: .resolved,
            uri: uri,
            caller: caller.id,
            timestamp: clock()
        ))

        // 6. Cache set.
        await cache.set(uri, value)

        return value
    }
}
