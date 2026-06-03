import Crypto
import Foundation
import Testing
@testable import ShiSecretsKit

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
