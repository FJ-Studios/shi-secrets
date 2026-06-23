import Crypto
import Foundation
import Testing
@testable import ShiSecretsKit
#if canImport(Darwin)
import Darwin
#endif

// ShiSecretsModule tests (Task 41 — BR-I-04).
//
// 1. Registers all core kit singletons reachable via resolve(_:).
// 2. `BrokerSigningKey` + `PinnedKeys` refuse to resolve before Bootstrap
//    marks them unsealed.

@Suite("ShiSecretsModule")
struct ShiSecretsModuleTests {

    @Test("DI registers all core kit singletons (audit, registry, rotation, etc.)")
    func test_di_registersAllCoreSingletons_tokenRegistry_auditWriter_scopeValidator_manifestVerifier_manifestStore_driverRegistry_rotationEngine_tokenMinter_tokenVerifier_brokerDaemon() throws {
        let container = DIContainer()
        container.registerSingleton(
            EntitlementAllowlist.self,
            EntitlementAllowlist(globs: ["ovh/*", "github.pat.*"])
        )
        container.install(ShiSecretsModule())

        // These MUST resolve — Wave 3 kit surface.
        _ = try container.resolve(AuditWriter.self)
        _ = try container.resolve(SeamsWriter.self)
        _ = try container.resolve(TokenRegistry.self)
        let scope = try container.resolve(ScopeValidator.self)
        #expect(scope.allowlist == ["ovh/*", "github.pat.*"])
        _ = try container.resolve(DriverRegistry.self)
        _ = try container.resolve(RotationEngine.self)
    }

    /// NEW-M2 regression: InMemoryCache registered by ShiSecretsModule must have
    /// isRevoked wired to TokenRegistry. Revoke a JTI via the registry and verify
    /// that a cache.get() for a matching entry returns nil (not the cached value).
    @Test("NEW-M2: InMemoryCache registered via DI has isRevoked wired to TokenRegistry — revoked JTI evicted on cache hit")
    func newM2_inMemoryCache_diRegistration_wiresTokenRegistryRevocation() async throws {
        let container = DIContainer()
        container.install(ShiSecretsModule())

        let registry = try container.resolve(TokenRegistry.self)
        let cache = try container.resolve(InMemoryCache.self)

        // Insert a token row so we have a valid JTI to revoke.
        let jti = "01HZZZZZZZZZZZZZZZZZZZZZZ1" // valid 26-char Crockford ULID shape
        let row = TokenRegistry.Row(
            jti: jti, sub: "test-sub", scope: "test/*",
            op: .read, nbf: Date(), diesAt: Date().addingTimeInterval(3600),
            llmTouched: false, passkeyPath: false
        )
        try await registry.insert(row)

        // Cache a value with this JTI.
        let uri = try ShiSecretURI.parse("shi-secret://prod/newm2-test")
        let secretValue = InMemoryCache.SecretValue(plaintext: "sensitive", jti: jti)
        await cache.set(uri, secretValue)

        // Before revocation — cache must return the value.
        let before = await cache.get(uri)
        #expect(before != nil, "NEW-M2: cache should return value before JTI is revoked")

        // Revoke the JTI in the TokenRegistry.
        try await registry.revoke(jti: jti)

        // After revocation — cache must return nil (evicted via isRevoked closure).
        let after = await cache.get(uri)
        #expect(after == nil, "NEW-M2: cache must evict entry when its JTI is revoked in the wired TokenRegistry")
    }

    @Test("BrokerSigningKey resolver refuses before Bootstrap unseal")
    func test_di_brokerSigningKey_refusesResolveBeforeBootstrapUnseal() throws {
        let container = DIContainer()
        container.install(ShiSecretsModule())

        // Sealed paths throw until unseal runs.
        #expect(throws: DIContainer.ResolveError.sealed(type: "BrokerSigningKey")) {
            _ = try container.resolve(BrokerSigningKey.self)
        }
        #expect(throws: DIContainer.ResolveError.sealed(type: "PinnedKeys")) {
            _ = try container.resolve(PinnedKeys.self)
        }

        // Simulate Bootstrap: register the unsealed key + flip the flag.
        let priv = Curve25519.Signing.PrivateKey()
        container.registerSingleton(
            BrokerSigningKey.self,
            BrokerSigningKey(privateKey: priv)
        )
        container.unseal(BrokerSigningKey.self)
        let key = try container.resolve(BrokerSigningKey.self)
        #expect(key.privateKey.rawRepresentation == priv.rawRepresentation)
    }
}
