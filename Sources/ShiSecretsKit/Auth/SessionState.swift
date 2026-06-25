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

    // MARK: - W6.5 additions (brokerd session lifecycle)

    /// W6.5: cached token's `session_fingerprint` ≠ current session's.
    /// Typical cause: Linux SSH disconnect + reconnect, or Mac user
    /// logout + re-login. Operator MUST run `shi secrets login --reauth`.
    case lockedBySessionChange

    /// W6.5: brokerd's auto-refresh path failed; operator action required.
    /// Distinct from `.error(...)` which represents an environment failure;
    /// `.needsReauth` represents an upstream-Vault refusal that the operator
    /// must address (revoked API key, MFA escalation, manual cred rotation).
    case needsReauth(reason: ReauthReason)
}

// MARK: - W6.5 ReauthReason

/// W6.5: granular reason brokerd surfaced `.needsReauth(...)`. Lets the CLI
/// emit a more specific operator-facing remediation than a generic message.
public enum ReauthReason: String, Sendable, Equatable, Codable {
    /// 401 from Vaultwarden using cached `client_credentials` — operator
    /// revoked the API key (Settings → Security → Keys → Rotate).
    case vaultRevokedKey
    /// Vaultwarden now requires MFA for the `client_credentials` grant;
    /// the daemon-side flow cannot satisfy that interactively.
    case upstreamMFAEscalation
    /// Operator regenerated `client_id` / `client_secret` outside the
    /// wizard flow; cached creds no longer authoritative.
    case clientCredsRotated
    /// Session fingerprint binding mismatch — typically reported as
    /// `.lockedBySessionChange` but kept here for granular telemetry.
    case sessionFingerprintMismatch
    /// Refresh failed for an indeterminate reason; raw error logged.
    case unknown
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
        case reason   // W6.5: associated value of .needsReauth
    }

    enum Kind: String, Codable {
        case locked, unlocking, unlocked, error
        // W6.5 additions:
        case lockedBySessionChange, needsReauth
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
        case .lockedBySessionChange:
            self = .lockedBySessionChange
        case .needsReauth:
            let reason = try c.decode(ReauthReason.self, forKey: .reason)
            self = .needsReauth(reason: reason)
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
        case .lockedBySessionChange:
            try c.encode(Kind.lockedBySessionChange, forKey: .kind)
        case .needsReauth(let reason):
            try c.encode(Kind.needsReauth, forKey: .kind)
            try c.encode(reason, forKey: .reason)
        }
    }
}

// MARK: - W6.5: operator-facing strings

public extension SessionState {
    /// Short summary suitable for one-line CLI rendering (used by W6.5b
    /// login / status / doctor verbs).
    var operatorMessage: String {
        switch self {
        case .locked:
            return "No vault credentials seeded. Run `shi secrets setup wizard`."
        case .unlocking:
            return "Token exchange in progress; please wait."
        case .unlocked(let exp):
            return "Logged in; token valid until \(ISO8601DateFormatter().string(from: exp))."
        case .error(let err):
            return "Session error: \(err). Check `~/.shikki/logs/secrets-brokerd.stderr.log`."
        case .lockedBySessionChange:
            return "Session changed (SSH reconnect or user re-login). Run `shi secrets login --reauth`."
        case .needsReauth(let reason):
            return "Re-authentication needed (\(reason.rawValue)). Run `shi secrets login --reauth`."
        }
    }
}
