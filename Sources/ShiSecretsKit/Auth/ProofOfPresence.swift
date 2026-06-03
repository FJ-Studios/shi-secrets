import Foundation

#if canImport(LocalAuthentication)
import LocalAuthentication
#endif

// ProofOfPresence — LAContext-based biometric/Touch ID re-auth gate for
// high-stakes operations (secret rotation, all-bot revoke, etc.).
//
// Wave 1 ships this type so it is importable by W2 callers. The W2 wave
// wires `require(reason:)` into SecretRotateCommand and TokenRevokeCommand.
//
// W1 contract: the type exists, compiles, and the method signature is
// locked. Tests for high-stakes gating live in W2 (BR-SM-16, BR-SM-17).
//
// BR-SM-16, BR-SM-17

/// Errors thrown when a proof-of-presence check fails.
public enum ProofOfPresenceError: Swift.Error, Sendable, Equatable {
    /// Device has no enrolled biometrics and no passcode fallback.
    case biometricNotAvailable

    /// The user cancelled the biometric prompt.
    case userCancelled

    /// Biometric check failed (wrong fingerprint, too many attempts, etc.).
    case authenticationFailed

    /// The system rejected the authentication attempt for a policy reason
    /// (e.g. lockout after too many failures).
    case systemPolicyFailure

    /// Platform does not support LocalAuthentication (e.g. Linux builds).
    case platformNotSupported
}

/// Gate for high-stakes operations: biometric/Touch ID re-auth via LAContext.
///
/// Usage (W2):
/// ```swift
/// try await ProofOfPresence.require(reason: "Rotate secret '\(name)'")
/// // ... perform high-stakes operation
/// ```
///
/// The gate uses `.deviceOwnerAuthentication` (not `.biometricsOnly`) so
/// a passcode fallback is available for operators without Touch ID enrolled
/// (BR-SM-17). Passkey fallback is also accepted via the policy evaluation.
public struct ProofOfPresence: Sendable {

    public init() {}

    /// Require proof-of-presence before proceeding. Throws if no biometric
    /// is enrolled, the user cancels, or the check fails.
    ///
    /// - Parameter reason: Localised string shown in the Touch ID / Face ID
    ///   prompt. Should describe the high-stakes operation being authorised.
    public func require(reason: String) async throws {
        #if canImport(LocalAuthentication) && !os(Linux)
        let context = LAContext()
        var policyError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &policyError) else {
            throw ProofOfPresenceError.biometricNotAvailable
        }

        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Swift.Error>) in
            context.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: reason
            ) { success, evaluationError in
                if success {
                    continuation.resume()
                } else if let err = evaluationError as? LAError {
                    switch err.code {
                    case .userCancel:
                        continuation.resume(throwing: ProofOfPresenceError.userCancelled)
                    case .authenticationFailed:
                        continuation.resume(throwing: ProofOfPresenceError.authenticationFailed)
                    case .biometryNotEnrolled, .passcodeNotSet:
                        continuation.resume(throwing: ProofOfPresenceError.biometricNotAvailable)
                    default:
                        continuation.resume(throwing: ProofOfPresenceError.systemPolicyFailure)
                    }
                } else {
                    continuation.resume(throwing: ProofOfPresenceError.authenticationFailed)
                }
            }
        }
        #else
        throw ProofOfPresenceError.platformNotSupported
        #endif
    }
}
