import Foundation
import Testing
@testable import ShiSecretsKit

// Schema tests for migration 0032_seams.sql (BR-J-02).
// The seams table is the Golden Seam Ledger — one row per anomaly-driven
// rotation (rotated / failed / bypassed).

@Suite("SeamsSchema")
struct SeamsSchemaTests {

    @Test("seams table has all required columns and CHECK constraints")
    func seamsHasAllRequiredColumnsAndCheckConstraints() throws {
        let sql = try SchemaTestSupport.load(migration: "0032_seams")

        #expect(sql.contains("CREATE TABLE seams"))

        let requiredColumns = [
            "id INTEGER PRIMARY KEY",
            "ts",
            "secret_name TEXT NOT NULL",
            "signal TEXT NOT NULL",
            "rotation_outcome TEXT NOT NULL",
            "notes",
        ]
        for column in requiredColumns {
            #expect(
                sql.contains(column),
                "seams SQL missing declaration for column: \(column)"
            )
        }

        #expect(sql.contains("rotation_outcome IN ('rotated','failed','bypassed')"))
    }

    @Test(
        "seams.rotation_outcome CHECK accepts 'rotated', 'failed', 'bypassed'",
        arguments: ["rotated", "failed", "bypassed"]
    )
    func seamsRotationOutcomeCheck(value: String) throws {
        let sql = try SchemaTestSupport.load(migration: "0032_seams")
        #expect(
            sql.contains("'\(value)'"),
            "seams SQL missing rotation_outcome allowlist value: \(value)"
        )
    }
}
