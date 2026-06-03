import Foundation
import Testing
@testable import ShiSecretsKit

// TokenRegistry insert tests (Task 13 — BR-A-05, BR-A-07).
//
// jti MUST be ULID (Crockford base32, 26 chars) and unique in the
// registry. Duplicate jti insertion rejects. Only metadata persists —
// the token bytes NEVER appear in any row (BR-A-07: the registry shape
// has no `bytes` / `envelope` column).

@Suite("TokenRegistryInsert")
struct TokenRegistryInsertTests {

    // ULID: 26 chars, Crockford base32 (no I, L, O, U).
    private static let validJti = "01JABCDEFGHJKMNPQRSTVWXYZ0"

    private func row(jti: String = TokenRegistryInsertTests.validJti) -> TokenRegistry.Row {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        return TokenRegistry.Row(
            jti: jti,
            sub: "bot:shi-mcp",
            scope: "ovh/*",
            op: .read,
            nbf: now,
            diesAt: now.addingTimeInterval(3600),
            llmTouched: false,
            passkeyPath: false,
            revoked: false,
            revokedAt: nil
        )
    }

    @Test("jti is ULID and unique in registry")
    func token_jti_isULID_andUniqueInRegistry() async throws {
        let registry = TokenRegistry()
        let r = row()
        try await registry.insert(r)

        // ULID shape: 26 chars, Crockford Base32 alphabet.
        #expect(r.jti.count == 26)
        let crockford = Set("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
        for ch in r.jti {
            #expect(crockford.contains(ch))
        }

        // Non-ULID jti is rejected at the type boundary.
        let bogus = TokenRegistry.Row(
            jti: "not-a-ulid",
            sub: "bot:x",
            scope: "ovh/*",
            op: .read,
            nbf: Date(),
            diesAt: Date().addingTimeInterval(60),
            llmTouched: false,
            passkeyPath: false,
            revoked: false,
            revokedAt: nil
        )
        await #expect(throws: ShikkiSBT.Error.self) {
            try await registry.insert(bogus)
        }
    }

    @Test("duplicate jti issuance — rejected")
    func token_jti_duplicateIssuance_rejected() async throws {
        let registry = TokenRegistry()
        try await registry.insert(row())
        await #expect(throws: ShikkiSBT.Error.duplicateJti(jti: Self.validJti)) {
            try await registry.insert(row())
        }
    }

    @Test("registry stores only jti + metadata — no token bytes")
    func token_bytes_notPersisted_registryStoresOnlyJtiAndMetadata() async throws {
        let registry = TokenRegistry()
        try await registry.insert(row())
        let stored = await registry.row(jti: Self.validJti)
        let persisted = try #require(stored)

        // Encode the stored row and verify no key named `bytes`,
        // `envelope`, or `token` appears in the JSON.
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(persisted)
        let json = String(data: data, encoding: .utf8) ?? ""
        #expect(!json.contains("\"bytes\""))
        #expect(!json.contains("\"envelope\""))
        #expect(!json.contains("\"token\""))
    }
}
