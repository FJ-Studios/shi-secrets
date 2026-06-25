// SystemNameBindingVerifier — v0.4.3 HIGH-2 fix (@security panel).
//
// Cross-validates the operator's system-name sidecar file
// (~/.shikki/etc/secrets/system-name) against the `bound_system_name`
// field persisted inside the Keychain credential blob.
//
// Attack model closed:
//   - HIGH-2 from v0.4.1 @security review: any process running as the
//     same user can write the sidecar file before/between/after the
//     wizard. Without this verifier, brokerd would load a poisoned
//     systemName and ScopePolicy would enforce the wrong blast-radius
//     prefix, letting the attacker read other systems' scopes (or its
//     own, depending on which name was injected).
//
// Verifier contract:
//   - Sidecar file ABSENT + Keychain `boundSystemName` ABSENT  → .ok(nil)
//     (legacy install pre-v0.4.3; no enforcement available)
//   - Sidecar file PRESENT + Keychain `boundSystemName` ABSENT → .ok(file)
//     (legacy blob; trust the file but warn so operator re-seeds)
//   - Sidecar ABSENT + Keychain PRESENT → .mismatch(.sidecarMissing)
//     (file was deleted; cannot verify, refuse)
//   - Both PRESENT + equal (case-insensitive) → .ok(canonical lowered)
//   - Both PRESENT + diverge → .mismatch(.fileDoesNotMatchKeychain)
//     (poisoned file OR rotated keychain; refuse boot)

import Foundation

public enum SystemNameBindingVerifier {

    public enum VerificationResult: Sendable, Equatable {
        case ok(systemName: String?)
        case mismatch(reason: MismatchReason)
    }

    public enum MismatchReason: Sendable, Equatable {
        case sidecarMissing
        case fileDoesNotMatchKeychain(fromFile: String, fromKeychain: String)

        public var operatorMessage: String {
            switch self {
            case .sidecarMissing:
                return "Keychain credentials are bound to a system name but the sidecar file is missing. Re-run `shi secrets setup wizard` to re-seed, or restore ~/.shikki/etc/secrets/system-name from backup."
            case .fileDoesNotMatchKeychain(let f, let k):
                return "System-name sidecar (\(f)) does not match the name bound into the Keychain credentials (\(k)). Refusing to boot — possible cache-poisoning attempt. Re-run `shi secrets setup wizard --force` if the divergence is intentional."
            }
        }
    }

    /// Verify the sidecar file against the credential blob.
    ///
    /// - Parameters:
    ///   - credentialsBoundName: `VaultwardenCredentials.boundSystemName`
    ///     (nil for pre-v0.4.3 blobs).
    ///   - sidecarName: the value loaded from
    ///     `~/.shikki/etc/secrets/system-name` (nil if file absent).
    public static func verify(
        credentialsBoundName: String?,
        sidecarName: String?
    ) -> VerificationResult {
        let credLowered = credentialsBoundName?.lowercased()
        let fileLowered = sidecarName?.lowercased()

        // Both absent → legacy install with no isolation; ScopePolicy disabled.
        if credLowered == nil && fileLowered == nil {
            return .ok(systemName: nil)
        }

        // Sidecar present, no Keychain binding → trust file (legacy blob path).
        if credLowered == nil, let file = fileLowered {
            return .ok(systemName: file)
        }

        // Keychain bound, sidecar missing → refuse.
        if credLowered != nil && fileLowered == nil {
            return .mismatch(reason: .sidecarMissing)
        }

        // Both present.
        if credLowered == fileLowered {
            return .ok(systemName: credLowered)
        }
        return .mismatch(reason: .fileDoesNotMatchKeychain(
            fromFile: fileLowered ?? "<absent>",
            fromKeychain: credLowered ?? "<absent>"
        ))
    }
}
