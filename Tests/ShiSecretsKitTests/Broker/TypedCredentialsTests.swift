import Foundation
import Testing
@testable import ShiSecretsKit

// TypedCredentialsTests — Codable round-trip + field-shape coverage
// for the Phase 0.3a (BR-G-04) typed credential envelopes.

@Suite("TypedCredentials")
struct TypedCredentialsTests {

    @Test("DBCredentials round-trips through JSON")
    func test_dbCredentials_codableRoundTrip() throws {
        let original = DBCredentials(
            host: "db.example.com",
            port: 5432,
            database: "app",
            user: "appuser",
            password: "p4ssw0rd",
            sslMode: "verify-full"
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(DBCredentials.self, from: data)
        #expect(decoded == original)
    }

    @Test("DBCredentials sslMode is optional")
    func test_dbCredentials_sslModeOptional() throws {
        let original = DBCredentials(host: "h", port: 1, database: "d", user: "u", password: "p")
        #expect(original.sslMode == nil)
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(DBCredentials.self, from: data)
        #expect(decoded.sslMode == nil)
    }

    @Test("OAuthPair round-trips through JSON with refresh token absent")
    func test_oauthPair_codableRoundTrip_noRefresh() throws {
        let expiry = Date(timeIntervalSince1970: 1_700_000_000)
        let original = OAuthPair(accessToken: "atk", refreshToken: nil, scope: nil, expiresAt: expiry)
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(OAuthPair.self, from: data)
        #expect(decoded == original)
        #expect(decoded.refreshToken == nil)
        #expect(decoded.scope == nil)
    }

    @Test("OAuthPair round-trips through JSON with all fields populated")
    func test_oauthPair_codableRoundTrip_full() throws {
        let expiry = Date(timeIntervalSince1970: 1_700_000_000)
        let original = OAuthPair(accessToken: "atk", refreshToken: "rtk", scope: "read:db write:audit", expiresAt: expiry)
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(OAuthPair.self, from: data)
        #expect(decoded == original)
    }

    @Test("ConnectionBundle round-trips through JSON")
    func test_connectionBundle_codableRoundTrip() throws {
        let expiry = Date(timeIntervalSince1970: 1_700_000_000)
        let original = ConnectionBundle(
            kind: "aws-iam",
            fields: [
                "access_key_id": "AKIA0000000",
                "secret_access_key": "shhh",
                "region": "eu-central-1",
                "session_token": "stk"
            ],
            expiresAt: expiry
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(ConnectionBundle.self, from: data)
        #expect(decoded == original)
    }

    @Test("ConnectionBundle expiresAt is optional")
    func test_connectionBundle_expiryOptional() {
        let bundle = ConnectionBundle(kind: "smtp", fields: ["host": "smtp.example.com"])
        #expect(bundle.expiresAt == nil)
    }
}
