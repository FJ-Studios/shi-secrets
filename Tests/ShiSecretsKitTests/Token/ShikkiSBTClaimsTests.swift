import Foundation
import Testing
@testable import ShiSecretsKit

// ShikkiSBT.Claims + Op + Error tests (Task 9 — BR-A-02, BR-A-04).
// Claims shape only — full validate() coverage lives in Task 10.

@Suite("ShikkiSBTClaims")
struct ShikkiSBTClaimsTests {

    @Test("all required claims present — issuance accepted")
    func allRequiredClaimsPresent_acceptsIssuance() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let claims = ShikkiSBT.Claims(
            sub: "bot:shi-mcp-ovh",
            scope: "ovh.dns.read:example.com",
            op: .read,
            ttl: 3600,
            jti: "01JABCDEFGHIJKLMNOPQRSTUVW",
            nbf: now,
            diesAt: now.addingTimeInterval(3600),
            llmTouched: true
        )
        #expect(claims.sub == "bot:shi-mcp-ovh")
        #expect(claims.op == .read)
        #expect(claims.ttl == 3600)
        #expect(claims.llmTouched == true)
    }

    @Test(
        "Op enum accepts 'read' and 'rotate'",
        arguments: [ShikkiSBT.Op.read, ShikkiSBT.Op.rotate]
    )
    func opEnumReadAndRotateAccepted(op: ShikkiSBT.Op) throws {
        let data = try JSONEncoder().encode(op)
        let decoded = try JSONDecoder().decode(ShikkiSBT.Op.self, from: data)
        #expect(decoded == op)
        // The wire format is a lowercase string literal.
        let raw = String(data: data, encoding: .utf8)
        #expect(raw == "\"\(op.rawValue)\"")
    }

    @Test(
        "Op enum rejects arbitrary strings",
        arguments: ["write", "delete", "MINT", "Read", ""]
    )
    func opEnumArbitraryStringRejected(raw: String) throws {
        let payload = "\"\(raw)\"".data(using: .utf8)!
        #expect(throws: DecodingError.self) {
            _ = try JSONDecoder().decode(ShikkiSBT.Op.self, from: payload)
        }
    }
}
