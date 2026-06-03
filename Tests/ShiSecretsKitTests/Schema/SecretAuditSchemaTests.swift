import Foundation
import Testing
@testable import ShiSecretsKit

// Schema tests for migration 0031_secret_audit.sql.
//
// Reads the raw SQL resource and asserts column shape + CHECK constraints
// against BR-J-01, BR-J-04, BR-J-05. No libsql dependency — regex scans the
// CREATE TABLE statement textually so these tests run in every environment.

@Suite("SecretAuditSchema")
struct SecretAuditSchemaTests {

    @Test("secret_audit table has all required columns and CHECK constraints")
    func secretAuditHasAllRequiredColumnsAndCheckConstraints() throws {
        let sql = try SchemaTestSupport.load(migration: "0031_secret_audit")

        // Table name
        #expect(sql.contains("CREATE TABLE secret_audit"))

        // Required columns per BR-J-01
        let requiredColumns = [
            "id INTEGER PRIMARY KEY",
            "ts",
            "token_jti TEXT NOT NULL",
            "caller_uid",
            "caller_transport TEXT NOT NULL",
            "secret_name TEXT NOT NULL",
            "op TEXT NOT NULL",
            "allow TEXT NOT NULL",
            "reason",
            "llm_touched",
        ]
        for column in requiredColumns {
            #expect(
                sql.contains(column),
                "secret_audit SQL missing declaration for column: \(column)"
            )
        }

        // llm_touched BOOLEAN NOT NULL (BR-J-01: non-nullable)
        #expect(sql.range(of: #"llm_touched\s+BOOLEAN\s+NOT\s+NULL"#, options: .regularExpression) != nil)

        // CHECK constraints present
        #expect(sql.contains("CHECK (caller_transport IN ('unix','mcp'))")
             || sql.contains("CHECK(caller_transport IN ('unix','mcp'))"))
        #expect(sql.contains("CHECK (op IN ('read','rotate'))")
             || sql.contains("CHECK(op IN ('read','rotate'))"))
        #expect(sql.contains("CHECK (allow IN ('allow','deny'))")
             || sql.contains("CHECK(allow IN ('allow','deny'))"))
    }

    @Test(
        "secret_audit.caller_transport CHECK accepts 'unix' and 'mcp' only",
        arguments: ["unix", "mcp"]
    )
    func secretAuditCallerTransportCheckUnixOrMcp(value: String) throws {
        let sql = try SchemaTestSupport.load(migration: "0031_secret_audit")

        // The declared allowlist must contain this value verbatim.
        #expect(
            sql.contains("'\(value)'"),
            "secret_audit SQL missing caller_transport allowlist value: \(value)"
        )

        // Arbitrary values are NOT in the allowlist (smoke check).
        for forbidden in ["ssh", "udp", "http", "grpc"] {
            #expect(!sql.contains("caller_transport IN ('unix','mcp','\(forbidden)')"))
        }
    }

    @Test("secret_audit.op CHECK accepts 'read' and 'rotate' only")
    func secretAuditOpCheckReadOrRotate() throws {
        let sql = try SchemaTestSupport.load(migration: "0031_secret_audit")
        #expect(sql.contains("op IN ('read','rotate')"))
        // No unexpected extra ops in the allowlist.
        #expect(!sql.contains("op IN ('read','rotate','delete')"))
        #expect(!sql.contains("op IN ('read','rotate','mint')"))
    }

    @Test("secret_audit.allow CHECK accepts 'allow' and 'deny' only")
    func secretAuditAllowCheckAllowOrDeny() throws {
        let sql = try SchemaTestSupport.load(migration: "0031_secret_audit")
        #expect(sql.contains("allow IN ('allow','deny')"))
        #expect(!sql.contains("allow IN ('allow','deny','maybe')"))
    }
}
