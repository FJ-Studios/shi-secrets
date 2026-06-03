import Foundation
import Testing
@testable import ShiSecretsKit

// ShikkiSBT.Claims.validate() tests (Task 10 — BR-A-02, BR-A-03, BR-A-06).
//
// Enforces:
// - All 8 claims present (missingClaim).
// - ttl <= 3600 seconds (ttlAbove3600).
// - dies_at == nbf + ttl.
// - Serialized JSON output MUST NOT contain the substring "expires_at".

@Suite("ShikkiSBTValidation")
struct ShikkiSBTValidationTests {

    static func validClaims(now: Date = Date(timeIntervalSince1970: 1_700_000_000)) -> ShikkiSBT.Claims {
        ShikkiSBT.Claims(
            sub: "bot:shi-mcp-ovh",
            scope: "ovh.dns.read:example.com",
            op: .read,
            ttl: 3600,
            jti: "01JABCDEFGHIJKLMNOPQRSTUVW",
            nbf: now,
            diesAt: now.addingTimeInterval(3600),
            llmTouched: true
        )
    }

    @Test(
        "rejects issuance when a required claim is missing",
        arguments: [
            "sub", "scope", "jti",
        ]
    )
    func missingAnyRequiredClaim_rejectsIssuance(claim: String) throws {
        let base = Self.validClaims()
        // For string-valued claims we produce a clone with an empty value;
        // validate() treats empty strings as "missing". Time + numeric +
        // boolean claims are covered by their own range checks (ttl,
        // diesAt) and by the JSON-decode contract (required key missing →
        // DecodingError — exercised in T9 round-trip).
        var overrides: (sub: String?, scope: String?, jti: String?) = (nil, nil, nil)
        switch claim {
        case "sub":   overrides.sub = ""
        case "scope": overrides.scope = ""
        case "jti":   overrides.jti = ""
        default:      Issue.record("Unhandled claim key: \(claim)")
        }
        let weakened = ShikkiSBT.Claims(
            sub: overrides.sub ?? base.sub,
            scope: overrides.scope ?? base.scope,
            op: base.op,
            ttl: base.ttl,
            jti: overrides.jti ?? base.jti,
            nbf: base.nbf,
            diesAt: base.diesAt,
            llmTouched: base.llmTouched
        )
        #expect(throws: ShikkiSBT.Error.self) {
            try weakened.validate()
        }
    }

    @Test("ttl == 3600 accepted")
    func ttl_equalTo3600_accepted() throws {
        let claims = Self.validClaims()
        try claims.validate()
    }

    @Test(
        "ttl > 3600 rejected",
        arguments: [3601, 7200, 86400]
    )
    func ttl_above3600_rejected(ttl: Int) throws {
        let base = Self.validClaims()
        let claims = ShikkiSBT.Claims(
            sub: base.sub,
            scope: base.scope,
            op: base.op,
            ttl: ttl,
            jti: base.jti,
            nbf: base.nbf,
            diesAt: base.nbf.addingTimeInterval(TimeInterval(ttl)),
            llmTouched: base.llmTouched
        )
        #expect(throws: ShikkiSBT.Error.ttlAbove3600) {
            try claims.validate()
        }
    }

    @Test("dies_at must equal nbf + ttl")
    func diesAtEqualsNbfPlusTtl() throws {
        let base = Self.validClaims()
        // Valid path: dies_at == nbf + ttl accepted.
        try base.validate()

        // Skew diesAt by 60 seconds — well outside the 1s floating-point
        // tolerance — validate() MUST reject.
        let skewed = ShikkiSBT.Claims(
            sub: base.sub,
            scope: base.scope,
            op: base.op,
            ttl: base.ttl,
            jti: base.jti,
            nbf: base.nbf,
            diesAt: base.nbf.addingTimeInterval(TimeInterval(base.ttl + 60)),
            llmTouched: base.llmTouched
        )
        #expect(throws: ShikkiSBT.Error.self) {
            try skewed.validate()
        }
    }

    @Test("dies_at skew surfaces as `.badDiesAt` (U19)")
    func test_claimsValidate_badDiesAt_dedicatedError_U19() throws {
        // Review finding U19 — `dies_at != nbf + ttl` surfaces as
        // `.badDiesAt` rather than the overloaded
        // `missingClaim(name: "dies_at")`.
        let base = Self.validClaims()
        let skewed = ShikkiSBT.Claims(
            sub: base.sub, scope: base.scope, op: base.op, ttl: base.ttl,
            jti: base.jti, nbf: base.nbf,
            diesAt: base.nbf.addingTimeInterval(TimeInterval(base.ttl + 60)),
            llmTouched: base.llmTouched
        )
        #expect(throws: ShikkiSBT.Error.badDiesAt) {
            try skewed.validate()
        }
    }

    @Test("ULID shape failure surfaces as `.invalidJti` (U19)")
    func test_registryValidateULID_invalidJti_dedicatedError_U19() throws {
        // Review finding U19 — bad-length + non-Crockford chars surface
        // as `.invalidJti(reason:)` with a human-readable cause.
        do {
            try TokenRegistry.validateULID("short")
            Issue.record("expected invalidJti")
        } catch ShikkiSBT.Error.invalidJti {
            // ok
        } catch {
            Issue.record("expected invalidJti, got \(error)")
        }
        do {
            // 26 chars but with 'I' — not in Crockford.
            try TokenRegistry.validateULID("01JABCDEFGHIJKLMNOPQRSTUVW")
            Issue.record("expected invalidJti")
        } catch ShikkiSBT.Error.invalidJti {
            // ok
        } catch {
            Issue.record("expected invalidJti, got \(error)")
        }
    }

    @Test("serialized output never contains the string 'expires_at'")
    func serializedOutput_neverContainsExpiresAt() throws {
        let claims = Self.validClaims()
        try claims.validate()
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(claims)
        let json = String(data: data, encoding: .utf8) ?? ""
        #expect(
            !json.contains("expires_at"),
            "ShikkiSBT JSON output MUST NOT contain 'expires_at' (BR-A-06); actual JSON: \(json)"
        )
        // Sanity: dies_at MUST be present as the one expiry surface.
        #expect(json.contains("dies_at"))
    }
}
