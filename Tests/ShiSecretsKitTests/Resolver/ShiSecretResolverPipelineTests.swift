import Testing
import Foundation
@testable import ShiSecretsKit

/// Test doubles for the 6-step pipeline.

private struct AllowAllACL: ACLProvider {
    func check(caller: PeerCredential, namespace: String) async throws {}
}

private actor SpyBroker: ShiSecretBroker {
    var calls: [(uri: ShiSecretURI, caller: PeerCredential)] = []
    func requestEphemeralToken(for uri: ShiSecretURI, caller: PeerCredential) async throws -> EphemeralToken {
        calls.append((uri, caller))
        return EphemeralToken(value: "token-for-\(uri.qualifiedKey)", expiresAt: Date().addingTimeInterval(60))
    }
}

private actor SpyBackend: SecretsBackend {
    var calls: [(token: EphemeralToken, qualifiedKey: String)] = []
    func resolve(token: EphemeralToken, qualifiedKey: String) async throws -> InMemoryCache.SecretValue {
        calls.append((token, qualifiedKey))
        return InMemoryCache.SecretValue(plaintext: "secret-for-\(qualifiedKey)")
    }
}

@Suite("ShiSecretResolver — 6-step pipeline (TP-SSEC-04)")
struct ShiSecretResolverPipelineTests {

    private func uri(_ ns: String, _ key: String) -> ShiSecretURI {
        // swiftlint:disable:next force_try
        try! ShiSecretURI.parse("shi-secret://\(ns)/\(key)")
    }

    @Test("pipeline resolves uri via cache → ACL → broker → backend → audit → cache")
    func pipelineOrder() async throws {
        let cache = InMemoryCache(ttl: 30)
        let broker = SpyBroker()
        let backend = SpyBackend()
        let sink = InMemoryAuditSink()

        let resolver = ShiSecretResolver(
            cache: cache,
            acl: AllowAllACL(),
            broker: broker,
            backend: backend,
            auditLog: AuditLog(sink: sink)
        )

        let value = try await resolver.resolve(
            uri: uri("obyw", "pb-admin"),
            caller: PeerCredential(id: "test")
        )

        #expect(value.plaintext == "secret-for-obyw/pb-admin")

        // Broker + backend each called once on cold path.
        let brokerCalls = await broker.calls.count
        let backendCalls = await backend.calls.count
        #expect(brokerCalls == 1)
        #expect(backendCalls == 1)

        // Audit recorded a single `.resolved`.
        let events = await sink.events
        #expect(events.count == 1)
        #expect(events.first?.kind == .resolved)
        #expect(events.first?.caller == "test")

        // Cache populated for re-resolve.
        let cacheCount = await cache.count()
        #expect(cacheCount == 1)
    }

    @Test("warm cache hit short-circuits broker/backend")
    func warmCacheShortCircuits() async throws {
        let cache = InMemoryCache(ttl: 30)
        let broker = SpyBroker()
        let backend = SpyBackend()
        let sink = InMemoryAuditSink()

        let resolver = ShiSecretResolver(
            cache: cache,
            acl: AllowAllACL(),
            broker: broker,
            backend: backend,
            auditLog: AuditLog(sink: sink)
        )

        let u = uri("obyw", "pb-admin")
        _ = try await resolver.resolve(uri: u, caller: PeerCredential(id: "test"))
        _ = try await resolver.resolve(uri: u, caller: PeerCredential(id: "test"))

        let brokerCalls = await broker.calls.count
        let backendCalls = await backend.calls.count
        #expect(brokerCalls == 1, "broker called only on cold-path")
        #expect(backendCalls == 1, "backend called only on cold-path")

        let events = await sink.events
        #expect(events.count == 2)
        #expect(events[0].kind == .resolved)
        #expect(events[1].kind == .cacheHit)
    }

    @Test("BR-SSEC-09: @db audit unreachable → resolver FAILS CLOSED")
    func auditUnreachableFailsClosed() async throws {
        let cache = InMemoryCache(ttl: 30)
        let broker = SpyBroker()
        let backend = SpyBackend()
        let sink = InMemoryAuditSink()
        await sink.setFailNext(true)

        let resolver = ShiSecretResolver(
            cache: cache,
            acl: AllowAllACL(),
            broker: broker,
            backend: backend,
            auditLog: AuditLog(sink: sink)
        )

        do {
            _ = try await resolver.resolve(
                uri: uri("obyw", "pb-admin"),
                caller: PeerCredential(id: "test")
            )
            Issue.record("Expected AuditLogUnreachableError")
        } catch is AuditLogUnreachableError {
            // Expected — fail closed.
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }
}
