import Foundation
import Testing
@testable import ShiSecretsKit

// ScopeValidatorGlobMatchingTests (T15-T17).
//
// W4.1 of spec e8c4a921-7d3b-4f5e-9a2c-1d6b8f4e3a91
// RED-FIRST: written before glob matching was implemented in ScopeValidator.
//
// Current ScopeValidator.validate uses allowlist.contains(pattern) — EXACT match.
// Glob matching must be added so that:
//   - "**" matches any scope (dev-mode wildcard)
//   - "foo/*" matches "foo/bar" but not "foo/bar/baz"
//   - "verify-*" matches "verify-phase-1" but not "prod-verify-phase-1"

@Suite("ScopeValidator Glob Matching")
struct ScopeValidatorGlobMatchingTests {

    // MARK: - T15: glob_doubleStar_matchesEverything

    @Test("T15 glob_doubleStar_matchesEverything — ** matches any scope")
    func glob_doubleStar_matchesEverything() throws {
        let validator = try ScopeValidator(allowlist: ["**"])

        // Simple flat scope
        #expect(throws: Never.self) {
            try validator.validate(pattern: "foo")
        }

        // Nested scope
        #expect(throws: Never.self) {
            try validator.validate(pattern: "foo/bar")
        }

        // Deep nested scope
        #expect(throws: Never.self) {
            try validator.validate(pattern: "a/b/c")
        }
    }

    // MARK: - T16: glob_singleStar_matchesOneSegment

    @Test("T16 glob_singleStar_matchesOneSegment — foo/* matches one path segment")
    func glob_singleStar_matchesOneSegment() throws {
        let validator = try ScopeValidator(allowlist: ["foo/*"])

        // Single segment after foo/
        #expect(throws: Never.self) {
            try validator.validate(pattern: "foo/bar")
        }

        // Two segments — should NOT match foo/* (only one segment allowed)
        #expect(throws: ScopeValidator.ValidationError.self) {
            try validator.validate(pattern: "foo/bar/baz")
        }
    }

    // MARK: - T17: glob_literalPrefix_matchesExactSegment

    @Test("T17 glob_literalPrefix_matchesExactSegment — verify-* matches by prefix")
    func glob_literalPrefix_matchesExactSegment() throws {
        let validator = try ScopeValidator(allowlist: ["verify-*"])

        // Direct match: verify- prefix
        #expect(throws: Never.self) {
            try validator.validate(pattern: "verify-phase-1")
        }

        // Does NOT match prod-verify-phase-1 (prefix mismatch)
        #expect(throws: ScopeValidator.ValidationError.self) {
            try validator.validate(pattern: "prod-verify-phase-1")
        }
    }
}
