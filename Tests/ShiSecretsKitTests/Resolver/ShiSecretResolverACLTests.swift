import Testing
import Foundation
@testable import ShiSecretsKit

private struct DenyAllACL: ACLProvider {
    func check(caller: PeerCredential, namespace: String) async throws {
        struct DenyError: Error {}
        throw DenyError()
    }
}

private struct AllowMatchingACL: ACLProvider {
    let allowedNamespace: String
    func check(caller: PeerCredential, namespace: String) async throws {
        if namespace != allowedNamespace {
            struct ACLBlock: Error {}
            throw ACLBlock()
        }
    }
}

private actor UnreachableBroker: ShiSecretBroker {
    func requestEphemeralToken(for uri: ShiSecretURI, caller: PeerCredential) async throws -> EphemeralToken {
        struct ShouldNotBeCalled: Error {}
        throw ShouldNotBeCalled()
    }
}

private actor UnreachableBackend: SecretsBackend {
    func resolve(token: EphemeralToken, qualifiedKey: String) async throws -> InMemoryCache.SecretValue {
        struct ShouldNotBeCalled: Error {}
        throw ShouldNotBeCalled()
    }
}

@Suite("ShiSecretResolver — ACL gating (TP-SSEC-05)")
struct ShiSecretResolverACLTests {

    private func uri(_ ns: String, _ key: String) -> ShiSecretURI {
        // swiftlint:disable:next force_try
        try! ShiSecretURI.parse("shi-secret://\(ns)/\(key)")
    }

    @Test("ACL denied → ACLDeniedError, broker/backend NEVER called")
    func deniedShortCircuits() async {
        let sink = InMemoryAuditSink()
        let resolver = ShiSecretResolver(
            cache: InMemoryCache(),
            acl: DenyAllACL(),
            broker: UnreachableBroker(),
            backend: UnreachableBackend(),
            auditLog: AuditLog(sink: sink)
        )

        do {
            _ = try await resolver.resolve(
                uri: uri("obyw", "pb-admin"),
                caller: PeerCredential(id: "intruder")
            )
            Issue.record("Expected ACLDeniedError")
        } catch let err as ACLDeniedError {
            #expect(err.caller == "intruder")
            #expect(err.namespace == "obyw")
        } catch {
            Issue.record("Unexpected error: \(error)")
        }

        // The rejection should still be audit-logged.
        let events = await sink.events
        #expect(events.count == 1)
        #expect(events.first?.kind == .rejected)
    }

    @Test("ACL allows matching namespace, denies other")
    func perNamespaceAllowlist() async throws {
        let sink = InMemoryAuditSink()
        let broker = MatchingBroker()
        let backend = MatchingBackend()
        let resolver = ShiSecretResolver(
            cache: InMemoryCache(),
            acl: AllowMatchingACL(allowedNamespace: "obyw"),
            broker: broker,
            backend: backend,
            auditLog: AuditLog(sink: sink)
        )

        // Allowed namespace → success.
        let v = try await resolver.resolve(
            uri: uri("obyw", "pb-admin"),
            caller: PeerCredential(id: "test")
        )
        #expect(v.plaintext == "secret-for-obyw/pb-admin")

        // Denied namespace → ACLDeniedError.
        do {
            _ = try await resolver.resolve(
                uri: uri("cliff-tech", "api-token"),
                caller: PeerCredential(id: "test")
            )
            Issue.record("Expected ACLDeniedError for cliff-tech namespace")
        } catch is ACLDeniedError {
            // Expected.
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }
}

private actor MatchingBroker: ShiSecretBroker {
    func requestEphemeralToken(for uri: ShiSecretURI, caller: PeerCredential) async throws -> EphemeralToken {
        EphemeralToken(value: "tok", expiresAt: Date().addingTimeInterval(60))
    }
}

private actor MatchingBackend: SecretsBackend {
    func resolve(token: EphemeralToken, qualifiedKey: String) async throws -> InMemoryCache.SecretValue {
        InMemoryCache.SecretValue(plaintext: "secret-for-\(qualifiedKey)")
    }
}
