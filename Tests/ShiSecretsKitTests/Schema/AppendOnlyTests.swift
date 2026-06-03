import Foundation
import Testing
@testable import ShiSecretsKit

// Schema tests for migration 0034_append_only_triggers.sql (BR-G-05, BR-J-06).
//
// The broker MUST reject UPDATE and DELETE statements against secret_audit
// and seams — both tables are append-only audit surfaces. These tests do NOT
// exercise a live sqlite engine (that belongs in integration tests); they
// assert that the migration declares BEFORE UPDATE / BEFORE DELETE triggers
// that RAISE(ABORT) with the 'append_only_violation' error string.

@Suite("AppendOnly")
struct AppendOnlyTests {

    @Test("secret_audit append-only trigger rejects UPDATE")
    func secretAuditRejectsUpdate() throws {
        let sql = try SchemaTestSupport.load(migration: "0034_append_only_triggers")
        #expect(sql.range(
            of: #"CREATE TRIGGER\s+\S*secret_audit\S*_no_update\s+BEFORE\s+UPDATE\s+ON\s+secret_audit"#,
            options: .regularExpression
        ) != nil)
        #expect(sql.contains("RAISE EXCEPTION 'append_only_violation'"))
    }

    @Test("secret_audit append-only trigger rejects DELETE")
    func secretAuditRejectsDelete() throws {
        let sql = try SchemaTestSupport.load(migration: "0034_append_only_triggers")
        #expect(sql.range(
            of: #"CREATE TRIGGER\s+\S*secret_audit\S*_no_delete\s+BEFORE\s+DELETE\s+ON\s+secret_audit"#,
            options: .regularExpression
        ) != nil)
    }

    @Test("seams append-only trigger rejects UPDATE and DELETE")
    func seamsRejectsUpdateAndDelete() throws {
        let sql = try SchemaTestSupport.load(migration: "0034_append_only_triggers")
        #expect(sql.range(
            of: #"CREATE TRIGGER\s+\S*seams\S*_no_update\s+BEFORE\s+UPDATE\s+ON\s+seams"#,
            options: .regularExpression
        ) != nil)
        #expect(sql.range(
            of: #"CREATE TRIGGER\s+\S*seams\S*_no_delete\s+BEFORE\s+DELETE\s+ON\s+seams"#,
            options: .regularExpression
        ) != nil)
    }
}
