import Foundation
import Testing
@testable import ShiSecretsKit

// Resource loader + regex helpers shared by the schema test suites.
// Migration SQL ships as a bundle resource under Sources/ShiSecretsKit/Migrations
// and is read textually — no libsql / sqlite3 is required for Wave 1 shape tests.

enum SchemaTestSupport {

    /// Loads a migration SQL file by stem (e.g. "0031_secret_audit") from the
    /// ShiSecretsKit bundle. Internal whitespace is collapsed so assertions
    /// can compare on canonical form without caring about column-alignment
    /// padding in the source file.
    static func load(migration stem: String) throws -> String {
        guard let url = Bundle.module.url(
            forResource: stem,
            withExtension: "sql",
            subdirectory: "Migrations"
        ) else {
            Issue.record("Migration resource not found in bundle: \(stem).sql")
            throw SchemaTestError.resourceNotFound(stem: stem)
        }
        let raw = try String(contentsOf: url, encoding: .utf8)
        return normalize(stripComments(raw))
    }

    /// Strips `-- …` line comments. Schema tests assert on the executable SQL
    /// only — the `expires_at` hygiene scan (BR-A-06) must not trip on a
    /// comment like "this column is NOT named expires_at".
    static func stripComments(_ sql: String) -> String {
        sql
            .split(separator: "\n", omittingEmptySubsequences: false)
            .map { line -> String in
                if let range = line.range(of: "--") {
                    return String(line[..<range.lowerBound])
                }
                return String(line)
            }
            .joined(separator: "\n")
    }

    /// Collapses runs of whitespace (including newlines) into a single space so
    /// textual assertions are insensitive to formatting. Leading/trailing
    /// whitespace is trimmed.
    static func normalize(_ sql: String) -> String {
        let collapsed = sql
            .replacingOccurrences(of: #"[\t ]+"#, with: " ", options: .regularExpression)
            .replacingOccurrences(of: #"\s*\n\s*"#, with: " ", options: .regularExpression)
            .replacingOccurrences(of: #" +"#, with: " ", options: .regularExpression)
        return collapsed.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Returns the CREATE TABLE body between `(` and the matching `)` for the
    /// named table. Used to scope column / CHECK assertions to a single table.
    static func createTableBody(_ sql: String, table: String) -> String? {
        let pattern = #"CREATE TABLE\s+"# + table + #"\s*\("#
        guard let range = sql.range(of: pattern, options: .regularExpression) else {
            return nil
        }
        // Find the matching closing paren (supports nested parens in CHECK).
        var depth = 0
        var index = range.upperBound
        let start = index
        while index < sql.endIndex {
            let char = sql[index]
            if char == "(" { depth += 1 }
            if char == ")" {
                if depth == 0 {
                    return String(sql[start..<index])
                }
                depth -= 1
            }
            index = sql.index(after: index)
        }
        return nil
    }
}

enum SchemaTestError: Error, Equatable {
    case resourceNotFound(stem: String)
}
