// SystemNamePolicy — validation + default-derivation for a brokerd install's
// per-system name (W6.5c, F-PSA-2).
//
// Each shi-secrets-brokerd install is bound to ONE system name (e.g. `mac-laptop`,
// `nuc-dev`, `ci-runner-1`). The system name drives the Bitwarden collection scope
// `shi/system/<name>/**` that the brokerd is permitted to read.
//
// Default derivation: `<hostname>-shikki` (operator can override during wizard).
// Validation: lowercase alphanumeric + dashes, 1 ≤ len ≤ 32. No leading/trailing
// dashes, no consecutive dashes, must start with an alphanumeric.
//
// Why these bounds: collection paths surface in Bitwarden URLs + CLI listings;
// keeping them short and shell-safe avoids quoting nightmares.

import Foundation

public enum SystemNamePolicy {

    /// Maximum permitted length of a system name.
    public static let maxLength = 32

    /// Minimum permitted length of a system name.
    public static let minLength = 1

    /// Validates a candidate system name. Returns `.success(name)` with the
    /// canonicalised name (lowercased) or `.failure(reason)`.
    public static func validate(_ candidate: String) -> Result<String, ValidationError> {
        let trimmed = candidate.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return .failure(.empty) }
        guard trimmed.count >= minLength else { return .failure(.tooShort(min: minLength)) }
        guard trimmed.count <= maxLength else { return .failure(.tooLong(max: maxLength)) }

        let lowered = trimmed.lowercased()
        // Allowed alphabet: a-z, 0-9, -
        for scalar in lowered.unicodeScalars {
            guard isAllowed(scalar) else {
                return .failure(.invalidCharacter(scalar: scalar))
            }
        }
        guard let first = lowered.unicodeScalars.first, isAlphanumeric(first) else {
            return .failure(.mustStartWithAlphanumeric)
        }
        guard let last = lowered.unicodeScalars.last, isAlphanumeric(last) else {
            return .failure(.mustEndWithAlphanumeric)
        }
        if lowered.contains("--") {
            return .failure(.consecutiveDashes)
        }
        return .success(lowered)
    }

    /// Derives a sensible default system name. Format: `<hostname-prefix>-shikki`.
    /// `hostname` defaults to `Host.current().localizedName` on Apple platforms;
    /// callers may pass any string for testability.
    public static func defaultName(hostname: String) -> String {
        let cleaned = hostname
            .lowercased()
            .replacingOccurrences(of: ".local", with: "")
            .replacingOccurrences(of: " ", with: "-")
        let prefix = cleaned.unicodeScalars
            .prefix(maxLength - "-shikki".count)
            .filter { isAllowed($0) }
            .map { String($0) }
            .joined()
        let stripped = stripDashes(prefix)
        if stripped.isEmpty {
            // MED-3 fix (@security panel): empty hostname previously returned
            // the literal "shikki" — two machines with all-symbol hostnames
            // would collide and gain mutual scope access. Append a short
            // entropy suffix so each install gets a unique name.
            let suffix = String(UUID().uuidString.prefix(8)).lowercased()
            return "shikki-\(suffix)"
        }
        return "\(stripped)-shikki"
    }

    // MARK: - Helpers

    private static func isAllowed(_ s: Unicode.Scalar) -> Bool {
        return isAlphanumeric(s) || s == "-"
    }

    private static func isAlphanumeric(_ s: Unicode.Scalar) -> Bool {
        return (s >= "a" && s <= "z") || (s >= "0" && s <= "9")
    }

    private static func stripDashes(_ s: String) -> String {
        var out = s
        while out.hasPrefix("-") { out.removeFirst() }
        while out.hasSuffix("-") { out.removeLast() }
        return out
    }

    // MARK: - Errors

    public enum ValidationError: Error, Sendable, Equatable {
        case empty
        case tooShort(min: Int)
        case tooLong(max: Int)
        case invalidCharacter(scalar: Unicode.Scalar)
        case mustStartWithAlphanumeric
        case mustEndWithAlphanumeric
        case consecutiveDashes

        public var operatorMessage: String {
            switch self {
            case .empty: return "system name is empty"
            case .tooShort(let n): return "system name must be at least \(n) character"
            case .tooLong(let n): return "system name must be at most \(n) characters"
            case .invalidCharacter(let s):
                return "system name contains invalid character '\(s)'; allowed: a-z 0-9 -"
            case .mustStartWithAlphanumeric: return "system name must start with a letter or digit"
            case .mustEndWithAlphanumeric: return "system name must end with a letter or digit"
            case .consecutiveDashes: return "system name may not contain consecutive dashes"
            }
        }
    }
}
