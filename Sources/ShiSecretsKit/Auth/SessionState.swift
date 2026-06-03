import Foundation

// SessionState — typed enum representing the broker's view of the
// Vaultwarden session lifecycle. Codable for the /health/session
// surface (Wave 3). Used by SessionCache to communicate state to
// BrokerDaemon without exposing raw token internals.
//
// Transitions:
//   .locked  → .unlocking  (KeychainVaultCredentials.load() called)
//   .unlocking → .unlocked  (VaultwardenClient.connect() returned a token)
//   .unlocking → .error     (Keychain read or token exchange failed)
//   .unlocked  → .locked    (SessionCache.invalidate() called)
//   .unlocked  → .unlocking (SessionCache auto-refresh triggered)
//   .error     → .unlocking (retry attempted via exponential backoff)
//
// BR-SM-06, BR-SM-07, BR-SM-08

/// The broker's current session lifecycle state.
public enum SessionState: Sendable, Equatable {

    /// No credentials loaded; broker refuses all token-mint requests.
    case locked

    /// Credentials loaded from Keychain; token exchange in progress.
    case unlocking

    /// Active access token held in SessionCache; valid until `expiresAt`.
    case unlocked(expiresAt: Date)

    /// A hard error from which the broker cannot auto-recover without
    /// operator intervention (e.g. Keychain item deleted, biometric
    /// permanently failed).
    case error(SessionError)
}

// MARK: - SessionError

/// Errors that put the session into the `.error` state.
public enum SessionError: Swift.Error, Sendable, Equatable, Codable {
    /// Keychain item not found — `shi secrets setup` not yet run (W2).
    case keychainItemMissing

    /// Keychain interaction not allowed (device locked, SIP restriction).
    case keychainInteractionNotAllowed

    /// macOS Security framework returned an unexpected OSStatus.
    case keychainOSError(status: Int32)

    /// Vaultwarden token endpoint returned a non-2xx status.
    case tokenExchangeFailed(httpStatus: Int)

    /// Access token could not be decoded from the response body.
    case tokenDecodingFailed

    /// TLS validation failed (CA mismatch or pin mismatch).
    case tlsValidationFailed

    /// Network unreachable (Vaultwarden endpoint not reachable).
    case networkUnreachable

    /// Credentials stored in Keychain are malformed (corrupt JSON blob).
    case credentialsMalformed

    /// Maximum consecutive refresh failures reached.
    case maxRefreshFailuresReached(count: Int)
}

// MARK: - Codable conformance for SessionState (Wave 3 /health/session)

extension SessionState: Codable {
    enum CodingKeys: String, CodingKey {
        case kind
        case expiresAt
        case error
    }

    enum Kind: String, Codable {
        case locked, unlocking, unlocked, error
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let kind = try c.decode(Kind.self, forKey: .kind)
        switch kind {
        case .locked:    self = .locked
        case .unlocking: self = .unlocking
        case .unlocked:
            let exp = try c.decode(Date.self, forKey: .expiresAt)
            self = .unlocked(expiresAt: exp)
        case .error:
            let err = try c.decode(SessionError.self, forKey: .error)
            self = .error(err)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .locked:
            try c.encode(Kind.locked, forKey: .kind)
        case .unlocking:
            try c.encode(Kind.unlocking, forKey: .kind)
        case .unlocked(let exp):
            try c.encode(Kind.unlocked, forKey: .kind)
            try c.encode(exp, forKey: .expiresAt)
        case .error(let err):
            try c.encode(Kind.error, forKey: .kind)
            try c.encode(err, forKey: .error)
        }
    }
}
