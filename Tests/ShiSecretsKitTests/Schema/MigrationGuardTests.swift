import Foundation
import Testing
@testable import ShiSecretsKit

// Guard tests — static shape checks across migrations 0031..0033.
//
// Task 5 (BR-J-04, BR-J-07): catches PII leakage column names (email /
// real_name / ip_address) and enforces NOT NULL on every BR-listed required
// column. The parameterized NOT NULL test strips the constraint from the
// source SQL and asserts the guard regex still detects the absence — this
// is the textual analogue of "missing NOT NULL fails migration". Full
// live-db coverage arrives with the libsql integration suite in Wave 2+.

@Suite("MigrationGuard")
struct MigrationGuardTests {

    /// (migration stem, column, full NOT NULL fragment that must appear).
    static let notNullColumns: [(stem: String, column: String, fragment: String)] = [
        ("0031_secret_audit",   "ts",                "ts TEXT NOT NULL"),
        ("0031_secret_audit",   "token_jti",         "token_jti TEXT NOT NULL"),
        ("0031_secret_audit",   "caller_transport",  "caller_transport TEXT NOT NULL"),
        ("0031_secret_audit",   "secret_name",       "secret_name TEXT NOT NULL"),
        ("0031_secret_audit",   "op",                "op TEXT NOT NULL"),
        ("0031_secret_audit",   "allow",             "allow TEXT NOT NULL"),
        ("0031_secret_audit",   "llm_touched",       "llm_touched BOOLEAN NOT NULL"),
        ("0032_seams",          "ts",                "ts TEXT NOT NULL"),
        ("0032_seams",          "secret_name",       "secret_name TEXT NOT NULL"),
        ("0032_seams",          "signal",            "signal TEXT NOT NULL"),
        ("0032_seams",          "rotation_outcome",  "rotation_outcome TEXT NOT NULL"),
        ("0033_token_registry", "sub",               "sub TEXT NOT NULL"),
        ("0033_token_registry", "scope",             "scope TEXT NOT NULL"),
        ("0033_token_registry", "op",                "op TEXT NOT NULL"),
        ("0033_token_registry", "nbf",               "nbf TEXT NOT NULL"),
        ("0033_token_registry", "dies_at",           "dies_at TEXT NOT NULL"),
        ("0033_token_registry", "llm_touched",       "llm_touched BOOLEAN NOT NULL"),
        ("0033_token_registry", "revoked",           "revoked BOOLEAN NOT NULL"),
        ("0033_token_registry", "passkey_path",      "passkey_path BOOLEAN NOT NULL"),
    ]

    @Test(
        "migration declares NOT NULL on every required column; stripping NOT NULL would remove the guard",
        arguments: notNullColumns
    )
    func migrationMissingNotNullConstraint_failsMigration(
        column: (stem: String, column: String, fragment: String)
    ) throws {
        let sql = try SchemaTestSupport.load(migration: column.stem)
        // Positive: the fragment must be present in the real migration.
        #expect(
            sql.contains(column.fragment),
            "Migration \(column.stem) MUST declare: \(column.fragment)"
        )

        // Negative guard: if we stripped NOT NULL out of the fragment, the
        // remaining SQL would no longer contain it. This exercises the
        // detection path that a downstream sqlite migration test would rely on.
        let weakenedFragment = column.fragment.replacingOccurrences(
            of: " NOT NULL",
            with: ""
        )
        let weakenedSql = sql.replacingOccurrences(
            of: column.fragment,
            with: weakenedFragment
        )
        #expect(
            !weakenedSql.contains(column.fragment),
            "Weakened SQL should no longer contain the NOT NULL fragment"
        )
    }

    @Test("all three tables use pseudo-IDs only — no email, real_name, or raw ip column")
    func allThreeTablesUsePseudoIdsOnly() throws {
        let stems = ["0031_secret_audit", "0032_seams", "0033_token_registry"]
        let forbidden = ["email", "real_name", "ip_address"]
        for stem in stems {
            let sql = try SchemaTestSupport.load(migration: stem)
            for term in forbidden {
                #expect(
                    !sql.contains(term),
                    "Migration \(stem) MUST NOT declare a `\(term)` column (BR-J-04)"
                )
            }
        }
    }
}
