// ScopePolicy — wire-enforced "this system reads ONLY `shi/system/<self>` +
// `shi/shared`" check (W6.5c, F-PSA-3).
//
// Every brokerd install carries a SystemName at boot. Every read/write through
// `shi secrets <verb>` is checked against this policy BEFORE the upstream
// Vaultwarden round-trip — so a compromised brokerd cannot exfiltrate items
// outside its declared blast radius, even if the upstream credentials would
// otherwise allow it.
//
// Path shape (Bitwarden collection path semantics):
//
//   shi/system/<my-name>/<key>     → allow (self)
//   shi/shared/<key>               → allow (shared bucket)
//   shi/system/<other-name>/<key>  → DENY
//   shi/personal/<key>             → DENY (operator's private vault, never broker-visible)
//   <anything else>                → DENY (default-closed)

import Foundation

public struct ScopePolicy: Sendable, Equatable {

    /// The system name this policy is bound to (e.g. `mac-laptop-shikki`).
    /// LOW-5 fix (@security panel): always lowercased so a case-mismatched
    /// system-name file cannot cause `decide()` to miss its own scope.
    public let systemName: String

    public init(systemName: String) {
        self.systemName = systemName.lowercased()
    }

    /// Returns `true` iff this system is permitted to read the given path.
    public func canRead(path: String) -> Bool {
        return decide(path).isAllowed
    }

    /// Returns the decision + reason for a path; useful for surfacing
    /// `DENY` reasons in operator-facing errors.
    public func decide(_ path: String) -> Decision {
        // v0.4.2 @tech-expert fix: lowercase the path too (was already
        // lowercasing systemName via LOW-5). Bitwarden collection paths
        // can have mixed-case entries; without normalisation
        // `shi/system/MAC-LAPTOP-SHIKKI/k` would be denied even when
        // systemName == "mac-laptop-shikki".
        let trimmed = path
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        guard !trimmed.isEmpty else { return .denied(reason: .emptyPath) }

        // Self-scope: `shi/system/<self>/...`
        let selfPrefix = "shi/system/\(systemName)/"
        if trimmed == "shi/system/\(systemName)" || trimmed.hasPrefix(selfPrefix) {
            return .allowed(rule: .selfScope)
        }

        // Shared bucket: `shi/shared/...`
        let sharedPrefix = "shi/shared/"
        if trimmed == "shi/shared" || trimmed.hasPrefix(sharedPrefix) {
            return .allowed(rule: .sharedScope)
        }

        // Personal vault: explicit deny (clearer error than the catch-all).
        if trimmed == "shi/personal" || trimmed.hasPrefix("shi/personal/") {
            return .denied(reason: .personalVault)
        }

        // Other system's scope: explicit deny.
        if trimmed.hasPrefix("shi/system/") {
            return .denied(reason: .otherSystemScope)
        }

        // Default closed.
        return .denied(reason: .outsideAllowedScopes)
    }

    // MARK: - Decision

    public enum Decision: Sendable, Equatable {
        case allowed(rule: AllowReason)
        case denied(reason: DenyReason)

        public var isAllowed: Bool {
            if case .allowed = self { return true }
            return false
        }
    }

    public enum AllowReason: String, Sendable, Equatable {
        case selfScope
        case sharedScope
    }

    public enum DenyReason: String, Sendable, Equatable {
        case emptyPath
        case personalVault
        case otherSystemScope
        case outsideAllowedScopes

        public var operatorMessage: String {
            switch self {
            case .emptyPath: return "empty path"
            case .personalVault: return "personal vault is operator-only; not broker-visible"
            case .otherSystemScope: return "path belongs to another system's scope; denied per blast-radius isolation"
            case .outsideAllowedScopes: return "path is outside the allowed scopes shi/system/<self>/** and shi/shared/**"
            }
        }
    }
}
