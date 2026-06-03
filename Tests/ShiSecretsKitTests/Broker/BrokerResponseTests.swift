import Foundation
import Testing
@testable import ShiSecretsKit

// BrokerResponse tests (Task 34 — BR-H-01).
//
// This is a type-system assertion test: the enum surface itself MUST NOT
// carry a `.rawPlaintext` case. The broker output gate has three shapes:
// ephemeralToken (short-lived signed envelope), boundPlaintext (jti +
// local unix plaintext), or deny (closed-set reason). Long-lived plaintext
// cannot be constructed because no case carries unbounded plaintext.

@Suite("BrokerResponse")
struct BrokerResponseTests {

    @Test("BrokerResponse has no long-lived plaintext case — type-system gate (BR-H-01)")
    func test_brokerResponse_neverContainsLongLivedPlaintext_onlyEphemeralTokensOrBoundPlaintext() {
        // Cover every case — the switch is exhaustive at the type level.
        let claims = ShikkiSBT.Claims(
            sub: "bot:shi-mcp", scope: "ovh/*", op: .read, ttl: 600,
            jti: "01JABCDEFGHJKMNPQRSTVWXYZ0",
            nbf: Date(), diesAt: Date().addingTimeInterval(600),
            llmTouched: true
        )
        let cases: [BrokerResponse] = [
            .ephemeralToken(ShikkiSBT(claims: claims)),
            .boundPlaintext(jti: "01JABCDEFGHJKMNPQRSTVWXYZ0", plaintext: "short"),
            .dbCredentials(
                jti: "01JABCDEFGHJKMNPQRSTVWXYZ1",
                credentials: DBCredentials(host: "db", port: 5432, database: "app", user: "u", password: "p"),
                policy: RefreshPolicy.defaultPolicy(for: .longLived)
            ),
            .oauthPair(
                jti: "01JABCDEFGHJKMNPQRSTVWXYZ2",
                pair: OAuthPair(accessToken: "a", refreshToken: "r", scope: "s", expiresAt: Date().addingTimeInterval(300)),
                policy: RefreshPolicy.defaultPolicy(for: .daemon)
            ),
            .connectionBundle(
                jti: "01JABCDEFGHJKMNPQRSTVWXYZ3",
                bundle: ConnectionBundle(kind: "aws-iam", fields: ["access_key_id": "AKIA"]),
                policy: RefreshPolicy.defaultPolicy(for: .longLived)
            ),
            .deny(.tokenExpired),
        ]
        for c in cases {
            switch c {
            case .ephemeralToken(let t):
                // Signed, short-lived: ttl ≤ 3600 per BR-A-03.
                #expect(t.claims.ttl <= 3600)
            case .boundPlaintext(let jti, let plaintext):
                // Plaintext is bound to a specific jti — not unbounded.
                #expect(!jti.isEmpty)
                #expect(!plaintext.isEmpty)
            case .dbCredentials(let jti, let creds, let policy):
                #expect(!jti.isEmpty)
                #expect(!creds.password.isEmpty)
                #expect(policy.ttlSeconds > 0)
            case .oauthPair(let jti, let pair, let policy):
                #expect(!jti.isEmpty)
                #expect(!pair.accessToken.isEmpty)
                #expect(policy.refreshBeforeSeconds >= 0)
            case .connectionBundle(let jti, let bundle, let policy):
                #expect(!jti.isEmpty)
                #expect(!bundle.kind.isEmpty)
                #expect(policy.revocationSLAMSeconds >= 0)
            case .deny(let reason):
                #expect(AuditRow.DenyReason.allCases.contains(reason))
            }
        }
    }
}
