import Foundation

// ScopeValidator — gates caller-supplied `scope` strings against the
// server-side glob allowlist loaded from the signed entitlement config.
//
// BR-H-04: unmatched globs reject with `scope_pattern_denied`.
// BR-H-06: regex syntax is always rejected — only glob patterns
//          (`*`, `?`, `.`, alphanumeric, `/`, `_`, `-`, `:`) are honored.
//
// The validator itself is a pure value type; the DenyReason mapping
// to an AuditRow happens in the broker's request handler (Wave 4).

public struct ScopeValidator: Sendable {

    public enum ValidationError: Swift.Error, Sendable, Equatable {
        case scopePatternDenied(pattern: String)
        case regexSyntaxForbidden(pattern: String)
        /// Scope exceeded `maxScopeLength`. Prevents silent truncation at
        /// the AuditWriter boundary (see finding #8 — reject overlong
        /// scopes at the validator so the audit row reflects the real
        /// scope verbatim up to the maxSecretNameLength ceiling).
        case scopeTooLong(length: Int)
    }

    /// Characters that betray regex syntax. Present in the pattern → reject.
    /// Note: `*` and `?` are glob wildcards and are NOT in this set; `.`
    /// is permitted because `github.pat.*` is a common glob form.
    public static let forbiddenRegexCharacters: Set<Character> = [
        "^", "$", "|", "(", ")", "[", "]", "{", "}", "\\", "+",
    ]

    /// Hard cap on scope-pattern length. Review finding U11 — a
    /// 10 MB scope string forced the validator into an O(n) scan; the
    /// cap closes the DoS surface. Set to 256 — well above the longest
    /// real-world glob but small enough that per-request work stays
    /// constant. The broker's audit-row `deriveSecretName` still
    /// truncates to `AuditWriter.maxSecretNameLength` (64) so oversized
    /// — but under-256 — scopes get recorded as their prefix.
    public static let maxScopeLength: Int = 256

    public let allowlist: [String]

    public init(allowlist: [String]) throws {
        // Sanity: every allowlisted pattern itself must be glob-safe.
        for entry in allowlist {
            for ch in entry where Self.forbiddenRegexCharacters.contains(ch) {
                throw ValidationError.regexSyntaxForbidden(pattern: entry)
            }
        }
        self.allowlist = allowlist
    }

    /// Validates a caller-supplied scope string. Throws on regex syntax,
    /// overlong patterns, or allowlist miss.
    public func validate(pattern: String) throws {
        if pattern.count > Self.maxScopeLength {
            throw ValidationError.scopeTooLong(length: pattern.count)
        }
        for ch in pattern where Self.forbiddenRegexCharacters.contains(ch) {
            throw ValidationError.regexSyntaxForbidden(pattern: pattern)
        }
        guard allowlist.contains(pattern) else {
            throw ValidationError.scopePatternDenied(pattern: pattern)
        }
    }
}
