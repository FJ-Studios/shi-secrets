import Foundation

// VaultwardenCredentials — value type that holds the Vaultwarden personal
// API key for a service-account-style client_credentials OAuth2 grant.
//
// Stored in macOS Keychain via KeychainVaultCredentials (W1). The server
// URL is NOT persisted here — it is resolved at runtime per the config
// hierarchy (config.yml vault.server → SHIKKI_VAULT_URL → DEV default).
// See VaultwardenClient.resolveServerURL() for the resolution chain.
//
// BR-SM-01, BR-SM-02 — no credentials in env vars; Keychain is the only
// authorized storage path.

/// Vaultwarden personal API key for the broker service account.
/// Codable so KeychainVaultCredentials can serialize to JSON before
/// writing to the Keychain blob. The JSON blob is opaque to every caller
/// except KeychainVaultCredentials — callers MUST NOT read raw Data
/// out of the Keychain themselves.
public struct VaultwardenCredentials: Codable, Sendable, Equatable {

    /// OAuth2 client_id from Vaultwarden (format: `user.<uuid>` for
    /// personal API key or a service-account ID for org vaults).
    public let clientID: String

    /// OAuth2 client_secret. Kept in memory only while the broker is
    /// performing token exchange; never written to disk outside of
    /// the Keychain blob.
    public let clientSecret: String

    /// Canonical Vaultwarden base URL. Stored alongside credentials so
    /// a moved deployment does not require a manual URL config update.
    /// At runtime VaultwardenClient ALWAYS re-validates this against the
    /// config hierarchy (config.yml → env → DEV default) before use.
    public let serverURL: URL

    /// v0.4.3 HIGH-2 fix (@security panel): the system name this credential
    /// blob was provisioned for. Persisted INSIDE the Keychain blob so the
    /// sidecar `~/.shikki/etc/secrets/system-name` file cannot be replaced
    /// out-of-band (cache-poisoning HIGH-2 from v0.4.1 @security review).
    /// Brokerd boot cross-validates the file against this field via
    /// `SystemNameBindingVerifier`. `nil` for legacy blobs seeded pre-v0.4.3.
    public let boundSystemName: String?

    public init(
        clientID: String,
        clientSecret: String,
        serverURL: URL,
        boundSystemName: String? = nil
    ) {
        self.clientID = clientID
        self.clientSecret = clientSecret
        self.serverURL = serverURL
        self.boundSystemName = boundSystemName
    }

    // MARK: - Codable keys (snake_case matches Vaultwarden API field names)

    enum CodingKeys: String, CodingKey {
        case clientID = "client_id"
        case clientSecret = "client_secret"
        case serverURL = "server_url"
        case boundSystemName = "bound_system_name"
    }
}
