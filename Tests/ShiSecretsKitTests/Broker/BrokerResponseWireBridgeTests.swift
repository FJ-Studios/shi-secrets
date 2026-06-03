import Foundation
import Testing
@testable import ShiSecretsKit

// BrokerResponseWireBridgeTests — round-trip coverage for the Phase 0.3b
// (BR-G-04 wire half) `BrokerResponse.toWireResponse(id:)` encoder.

@Suite("BrokerResponseWireBridge")
struct BrokerResponseWireBridgeTests {

    private func makeClaims() -> ShikkiSBT.Claims {
        ShikkiSBT.Claims(
            sub: "bot:shi-mcp",
            scope: "ovh/*",
            op: .read,
            ttl: 600,
            jti: "01JABCDEFGHJKMNPQRSTVWXYZ0",
            nbf: Date(timeIntervalSince1970: 1_700_000_000),
            diesAt: Date(timeIntervalSince1970: 1_700_000_600),
            llmTouched: true
        )
    }

    @Test("ephemeralToken → result envelope with type=ephemeralToken + claims")
    func test_ephemeralToken_encodesAsResultEnvelope() throws {
        let resp = BrokerResponse.ephemeralToken(ShikkiSBT(claims: makeClaims()))
        let wire = try resp.toWireResponse(id: "req-1")
        #expect(wire.id == "req-1")
        #expect(wire.error == nil)
        guard case .object(let obj) = wire.result! else { return #expect(Bool(false), "result must be object") }
        #expect(obj["type"] == .string("ephemeralToken"))
        // Claims is encoded as an object — discriminator preserved.
        if case .object(let claims) = obj["claims"]! {
            #expect(claims["sub"] == .string("bot:shi-mcp"))
            #expect(claims["scope"] == .string("ovh/*"))
            #expect(claims["llm_touched"] == .bool(true))
        } else {
            #expect(Bool(false), "claims must be encoded as object")
        }
    }

    @Test("boundPlaintext → result envelope with jti + plaintext")
    func test_boundPlaintext_encodesAsResultEnvelope() throws {
        let resp = BrokerResponse.boundPlaintext(jti: "j1", plaintext: "secret")
        let wire = try resp.toWireResponse(id: "req-2")
        guard case .object(let obj) = wire.result! else { return #expect(Bool(false), "result must be object") }
        #expect(obj["type"] == .string("boundPlaintext"))
        #expect(obj["jti"] == .string("j1"))
        #expect(obj["plaintext"] == .string("secret"))
    }

    @Test("dbCredentials → result envelope carries credentials + policy")
    func test_dbCredentials_encodesAsResultEnvelope() throws {
        let creds = DBCredentials(host: "db", port: 5432, database: "app", user: "u", password: "p")
        let policy = RefreshPolicy.defaultPolicy(for: .longLived)
        let resp = BrokerResponse.dbCredentials(jti: "j2", credentials: creds, policy: policy)
        let wire = try resp.toWireResponse(id: "req-3")
        guard case .object(let obj) = wire.result! else { return #expect(Bool(false), "result must be object") }
        #expect(obj["type"] == .string("dbCredentials"))
        #expect(obj["jti"] == .string("j2"))
        // credentials nested object
        if case .object(let credsObj) = obj["credentials"]! {
            #expect(credsObj["host"] == .string("db"))
            #expect(credsObj["password"] == .string("p"))
        } else { #expect(Bool(false), "credentials must be nested object") }
        // policy nested object
        if case .object(let polObj) = obj["policy"]! {
            #expect(polObj["ttlSeconds"] == .int(14_400))
        } else { #expect(Bool(false), "policy must be nested object") }
    }

    @Test("oauthPair → result envelope carries pair + policy")
    func test_oauthPair_encodesAsResultEnvelope() throws {
        let pair = OAuthPair(accessToken: "atk", refreshToken: "rtk", scope: nil, expiresAt: Date(timeIntervalSince1970: 1_700_000_000))
        let policy = RefreshPolicy.defaultPolicy(for: .daemon)
        let resp = BrokerResponse.oauthPair(jti: "j3", pair: pair, policy: policy)
        let wire = try resp.toWireResponse(id: "req-4")
        guard case .object(let obj) = wire.result! else { return #expect(Bool(false), "result must be object") }
        #expect(obj["type"] == .string("oauthPair"))
        if case .object(let pairObj) = obj["pair"]! {
            #expect(pairObj["accessToken"] == .string("atk"))
            #expect(pairObj["refreshToken"] == .string("rtk"))
        } else { #expect(Bool(false), "pair must be nested object") }
    }

    @Test("connectionBundle → result envelope carries bundle + policy")
    func test_connectionBundle_encodesAsResultEnvelope() throws {
        let bundle = ConnectionBundle(kind: "aws-iam", fields: ["access_key_id": "AKIA"])
        let resp = BrokerResponse.connectionBundle(
            jti: "j4",
            bundle: bundle,
            policy: RefreshPolicy.defaultPolicy(for: .longLived)
        )
        let wire = try resp.toWireResponse(id: "req-5")
        guard case .object(let obj) = wire.result! else { return #expect(Bool(false), "result must be object") }
        #expect(obj["type"] == .string("connectionBundle"))
        if case .object(let bundleObj) = obj["bundle"]! {
            #expect(bundleObj["kind"] == .string("aws-iam"))
        } else { #expect(Bool(false), "bundle must be nested object") }
    }

    @Test("deny(scopeDenied) → WireError with scope-violation code")
    func test_denyScope_mapsToScopeViolationCode() throws {
        let wire = try BrokerResponse.deny(.scopeDenied).toWireResponse(id: "req-6")
        #expect(wire.result == nil)
        #expect(wire.error?.code == WireErrorCode.scopeViolation)
        if case .object(let data) = wire.error?.data ?? .null {
            #expect(data["reason"] == .string("scope_denied"))
        } else { #expect(Bool(false), "error.data must carry reason payload") }
    }

    @Test("deny(brokerSessionInvalid) → bootstrap-failed code")
    func test_denyBrokerSession_mapsToBootstrapFailedCode() throws {
        let wire = try BrokerResponse.deny(.brokerSessionInvalid).toWireResponse(id: "req-7")
        #expect(wire.error?.code == WireErrorCode.bootstrapFailed)
    }

    @Test("deny(tokenExpired) → generic denied code")
    func test_denyTokenExpired_mapsToGenericDeniedCode() throws {
        let wire = try BrokerResponse.deny(.tokenExpired).toWireResponse(id: "req-8")
        #expect(wire.error?.code == WireErrorCode.denied)
    }

    @Test("All success WireResponse encode through JSONEncoder (round-trippable)")
    func test_allSuccessCases_encodeToJSON() throws {
        let cases: [BrokerResponse] = [
            .ephemeralToken(ShikkiSBT(claims: makeClaims())),
            .boundPlaintext(jti: "j1", plaintext: "p"),
            .dbCredentials(
                jti: "j2",
                credentials: DBCredentials(host: "h", port: 1, database: "d", user: "u", password: "p"),
                policy: RefreshPolicy.defaultPolicy(for: .daemon)
            ),
            .oauthPair(
                jti: "j3",
                pair: OAuthPair(accessToken: "a", refreshToken: nil, scope: nil, expiresAt: Date()),
                policy: RefreshPolicy.defaultPolicy(for: .interactive)
            ),
            .connectionBundle(
                jti: "j4",
                bundle: ConnectionBundle(kind: "smtp", fields: ["host": "smtp.example.com"]),
                policy: RefreshPolicy.defaultPolicy(for: .longLived)
            ),
        ]
        for c in cases {
            let wire = try c.toWireResponse(id: "x")
            let data = try encodeWireFrame(wire)
            #expect(data.last == 0x0A, "wire frame must end with \\n")
            #expect(data.count > 2, "non-empty frame")
        }
    }
}
