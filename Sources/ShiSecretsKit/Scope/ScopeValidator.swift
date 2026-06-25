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
    ///
    /// Each entry in `allowlist` is treated as a glob pattern:
    ///   - `**`  matches any scope at any depth.
    ///   - `*`   matches one path segment (no `/` characters).
    ///   - All other characters are matched literally.
    public func validate(pattern: String) throws {
        if pattern.count > Self.maxScopeLength {
            throw ValidationError.scopeTooLong(length: pattern.count)
        }
        for ch in pattern where Self.forbiddenRegexCharacters.contains(ch) {
            throw ValidationError.regexSyntaxForbidden(pattern: pattern)
        }
        let matched = allowlist.contains { globPattern in
            Self.globMatches(pattern: globPattern, scope: pattern)
        }
        guard matched else {
            throw ValidationError.scopePatternDenied(pattern: pattern)
        }
    }

    // MARK: - Glob matching

    /// Returns true when `pattern` (a glob) matches `scope` (a literal scope string).
    ///
    /// Rules:
    ///   - `**`        matches zero or more path segments (any character including `/`).
    ///   - `*`         matches exactly one path segment (no `/`).
    ///   - Other chars match literally.
    ///
    /// Implemented via recursive descent; the allowlist is small (≤50 entries)
    /// and scopes are short (≤256 chars) so no memoization is needed.
    public static func globMatches(pattern: String, scope: String) -> Bool {
        let p = Array(pattern)
        let s = Array(scope)
        return globMatchImpl(p: p, pIdx: 0, s: s, sIdx: 0)
    }

    private static func globMatchImpl(
        p: [Character], pIdx: Int,
        s: [Character], sIdx: Int
    ) -> Bool {
        var pi = pIdx
        var si = sIdx

        while pi < p.count {
            let pc = p[pi]

            if pc == "*" {
                // Check for "**"
                if pi + 1 < p.count && p[pi + 1] == "*" {
                    // "**" — match zero or more characters including "/"
                    // Skip consecutive ** groups
                    var nextPi = pi + 2
                    // Skip an optional "/" separator after **
                    if nextPi < p.count && p[nextPi] == "/" {
                        nextPi += 1
                    }
                    if nextPi == p.count {
                        // "**" at the end of the pattern → matches everything remaining
                        return true
                    }
                    // Try matching the rest of the pattern at every position in scope
                    for tryIdx in si...s.count {
                        if globMatchImpl(p: p, pIdx: nextPi, s: s, sIdx: tryIdx) {
                            return true
                        }
                    }
                    return false
                } else {
                    // Single "*" — match one segment (no "/")
                    pi += 1
                    // Advance si consuming non-"/" characters
                    while si < s.count && s[si] != "/" {
                        si += 1
                    }
                    // At this point si is either at end or at "/"
                    // Continue matching — the loop will handle the next character
                    continue
                }
            } else {
                // Literal character must match
                if si >= s.count || s[si] != pc {
                    return false
                }
                pi += 1
                si += 1
            }
        }

        // Pattern exhausted — scope must also be exhausted for a full match
        return si == s.count
    }
}
