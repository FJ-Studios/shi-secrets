import Foundation
import Testing
@testable import ShiSecretsKit

// ScopeValidator tests (Task 20 — BR-H-04, BR-H-06).
//
// Callers send `scope` strings; the broker validates each against a
// server-side allowlist of glob patterns loaded from the signed
// entitlement config (BR-H-04). Regex patterns are always rejected
// (BR-H-06); only glob syntax is honored.

@Suite("ScopeValidator")
struct ScopeValidatorTests {

    @Test("allowlisted glob pattern accepted")
    func scopeGlob_allowlistedPattern_accepted() throws {
        let validator = try ScopeValidator(allowlist: ["ovh/*", "brevo/*", "github.pat.*"])
        try validator.validate(pattern: "ovh/*")
        try validator.validate(pattern: "github.pat.*")
    }

    @Test("server allowlist mismatch → scope_pattern_denied")
    func scopeGlob_validatedAgainstServerAllowlist_unmatchedRejectedScopePatternDenied() throws {
        let validator = try ScopeValidator(allowlist: ["ovh/*"])
        #expect(throws: ScopeValidator.ValidationError.scopePatternDenied(pattern: "aws/*")) {
            try validator.validate(pattern: "aws/*")
        }
    }

    @Test(
        "regex metacharacters from caller → rejected, only glob honored",
        arguments: ["^ovh/.*$", "ovh|aws", "(ovh|brevo)", "[a-z]+", "ovh\\w+"]
    )
    func broker_regexPatternFromCaller_rejected_onlyGlobSyntaxHonoured(raw: String) throws {
        let validator = try ScopeValidator(allowlist: ["ovh/*"])
        #expect(throws: ScopeValidator.ValidationError.self) {
            try validator.validate(pattern: raw)
        }
    }

    @Test("scope pattern exceeding 256 chars → scopeTooLong (U11)")
    func test_scopeValidator_rejectsScopeAbove256Chars_U11() throws {
        // Review finding U11 — the 256-char cap closes the 10MB-scope
        // DoS surface.
        let validator = try ScopeValidator(allowlist: ["ovh/*"])
        let huge = String(repeating: "a", count: 257)
        #expect(throws: ScopeValidator.ValidationError.self) {
            try validator.validate(pattern: huge)
        }
        // Exactly 256 chars is the largest accepted length (subject to
        // allowlist match — we expect .scopePatternDenied here, not
        // .scopeTooLong, because the length check passes).
        let onTheLine = String(repeating: "a", count: 256)
        do {
            try validator.validate(pattern: onTheLine)
            Issue.record("expected scopePatternDenied")
        } catch ScopeValidator.ValidationError.scopePatternDenied {
            // ok — length check passed, allowlist check failed.
        } catch {
            Issue.record("expected scopePatternDenied, got \(error)")
        }
    }
}
