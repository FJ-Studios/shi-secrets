import Foundation
import Testing
@testable import ShiSecretsKit

// Schema tests for migration 0033_token_registry.sql (BR-J-03, BR-J-06).
// token_registry stores only jti + audit metadata — never token bytes (BR-A-07).

@Suite("TokenRegistrySchema")
struct TokenRegistrySchemaTests {

    @Test("token_registry table has all required columns with defaults")
    func tokenRegistryHasAllRequiredColumns() throws {
        let sql = try SchemaTestSupport.load(migration: "0033_token_registry")

        #expect(sql.contains("CREATE TABLE token_registry"))

        let requiredColumns = [
            "jti TEXT PRIMARY KEY",
            "sub TEXT NOT NULL",
            "scope TEXT NOT NULL",
            "op TEXT NOT NULL",
            "nbf TEXT NOT NULL",
            "dies_at TEXT NOT NULL",
            "llm_touched BOOLEAN NOT NULL",
            "revoked BOOLEAN NOT NULL DEFAULT FALSE",
            "revoked_at",
            "passkey_path BOOLEAN NOT NULL DEFAULT FALSE",
        ]
        for column in requiredColumns {
            #expect(
                sql.contains(column),
                "token_registry SQL missing declaration for column: \(column)"
            )
        }

        // BR-A-06 enforcement: the only expiry surface is dies_at. Expires_at
        // must not appear anywhere in the schema (also covered by Task 10 at
        // the serialization level).
        #expect(
            !sql.contains("expires_at"),
            "token_registry SQL must never reference expires_at (BR-A-06)"
        )
    }

    @Test("token_registry.op CHECK accepts 'read' and 'rotate' only")
    func tokenRegistryOpCheck() throws {
        let sql = try SchemaTestSupport.load(migration: "0033_token_registry")
        #expect(sql.contains("op IN ('read','rotate')"))
    }

    @Test("token_registry.revoked and passkey_path default FALSE")
    func tokenRegistryRevokedDefaultFalse_passkeyPathDefaultFalse() throws {
        let sql = try SchemaTestSupport.load(migration: "0033_token_registry")
        #expect(sql.contains("revoked BOOLEAN NOT NULL DEFAULT FALSE"))
        #expect(sql.contains("passkey_path BOOLEAN NOT NULL DEFAULT FALSE"))
    }
}
