import Crypto
import Foundation
import Testing
@testable import ShiSecretsKit

// EntitlementConfig tests (Task 21 — BR-D-06, BR-D-07).
//
// Every caller (local uid or MCP bearer) is mapped to a scope glob set
// at broker startup, loaded from a signed config. Runtime mutation
// without a fresh signature is rejected (BR-D-07). Callers outside
// their entitlement glob are rejected with scope_denied (BR-D-06).

@Suite("EntitlementConfig")
struct EntitlementConfigTests {

    private func sign(_ payload: EntitlementConfig.Payload, with key: Curve25519.Signing.PrivateKey) throws -> (Data, Data) {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let bytes = try encoder.encode(payload)
        let sig = try key.signature(for: bytes)
        return (bytes, Data(sig))
    }

    @Test("loaded from signed config at startup")
    func entitlement_loadedFromSignedConfigAtStartup() throws {
        let key = Curve25519.Signing.PrivateKey()
        let payload = EntitlementConfig.Payload(
            bindings: [
                EntitlementConfig.Binding(caller: "uid:1001", globs: ["ovh/*"]),
                EntitlementConfig.Binding(caller: "bearer:shi-mcp", globs: ["ovh/*", "brevo/*"]),
            ]
        )
        let (bytes, sig) = try sign(payload, with: key)
        let config = try EntitlementConfig.loadSigned(
            bytes: bytes,
            signature: sig,
            pub: key.publicKey
        )
        #expect(config.lookup(uidOrBearer: "uid:1001") == ["ovh/*"])
        #expect(config.lookup(uidOrBearer: "bearer:shi-mcp") == ["ovh/*", "brevo/*"])
    }

    @Test("runtime mutation without signature — reload rejected")
    func entitlement_runtimeMutationWithoutSignature_reloadRejected() throws {
        let key = Curve25519.Signing.PrivateKey()
        let payload = EntitlementConfig.Payload(
            bindings: [EntitlementConfig.Binding(caller: "uid:1001", globs: ["ovh/*"])]
        )
        let (bytes, sig) = try sign(payload, with: key)

        // Mutate the bytes without re-signing.
        var tampered = bytes
        if let idx = tampered.indices.first { tampered[idx] ^= 0x01 }

        #expect(throws: EntitlementConfig.LoadError.self) {
            _ = try EntitlementConfig.loadSigned(
                bytes: tampered,
                signature: sig,
                pub: key.publicKey
            )
        }
    }

    @Test(
        "caller outside entitlement glob → scope_denied",
        arguments: [AuditRow.Transport.unix, .mcp]
    )
    func caller_outsideEntitlementGlob_rejectedScopeDenied(transport: AuditRow.Transport) throws {
        let key = Curve25519.Signing.PrivateKey()
        let payload = EntitlementConfig.Payload(
            bindings: [EntitlementConfig.Binding(caller: "uid:1001", globs: ["ovh/*"])]
        )
        let (bytes, sig) = try sign(payload, with: key)
        let config = try EntitlementConfig.loadSigned(
            bytes: bytes,
            signature: sig,
            pub: key.publicKey
        )
        // A caller not present in the config has no globs — any request
        // is therefore outside their entitlement.
        let globs = config.lookup(uidOrBearer: transport == .unix ? "uid:9999" : "bearer:unknown")
        #expect(globs.isEmpty)
    }

    @Test(
        "caller within entitlement glob — allowed",
        arguments: [AuditRow.Transport.unix, .mcp]
    )
    func caller_withinEntitlementGlob_allowed(transport: AuditRow.Transport) throws {
        let key = Curve25519.Signing.PrivateKey()
        let payload = EntitlementConfig.Payload(
            bindings: [
                EntitlementConfig.Binding(caller: "uid:1001", globs: ["ovh/*"]),
                EntitlementConfig.Binding(caller: "bearer:shi-mcp", globs: ["ovh/*"]),
            ]
        )
        let (bytes, sig) = try sign(payload, with: key)
        let config = try EntitlementConfig.loadSigned(
            bytes: bytes,
            signature: sig,
            pub: key.publicKey
        )
        let key2 = transport == .unix ? "uid:1001" : "bearer:shi-mcp"
        #expect(config.lookup(uidOrBearer: key2).contains("ovh/*"))
    }
}
