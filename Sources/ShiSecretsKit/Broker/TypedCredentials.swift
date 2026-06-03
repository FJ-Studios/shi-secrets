import Foundation

// TypedCredentials — structured credential envelopes for consumers
// whose use-case can't be served by a raw string blob.
//
// Phase 0.3a (BR-G-04) of features/shikkisecrets-broker-completion.md.
//
// A `PostgresPool` caller needs `{host, port, database, user, password}`
// as named fields, not a `host=… port=… …` PG-DSN-style string they have
// to parse. Same for OAuth pairs (access + refresh + scope + expiry) and
// arbitrary connection bundles (e.g. AWS access-key + secret + region +
// session-token). Surfacing these as typed structs eliminates the
// stringly-typed parsing layer that every caller would otherwise
// hand-roll.
//
// All three types are `Codable + Equatable + Sendable` so they wire
// cleanly over the JSON-RPC layer (Phase 0.1 / 0.2) and over the
// in-process BrokerResponse enum (extended in this same phase).

/// Database connection fields. Useful for any caller that opens a
/// connection pool against Postgres / MySQL / similar — they get
/// named fields instead of parsing a DSN string.
public struct DBCredentials: Codable, Equatable, Sendable {
    public let host: String
    public let port: Int
    public let database: String
    public let user: String
    /// Plaintext password. The broker emits this only inside a
    /// `.boundPlaintext`-equivalent envelope path; the caller's
    /// contract is to discard it as soon as the connection pool is
    /// established and to never log it.
    public let password: String
    /// Optional connection-time TLS mode hint (e.g. "require",
    /// "verify-full"). Caller-side responsibility to honor.
    public let sslMode: String?

    public init(host: String, port: Int, database: String, user: String, password: String, sslMode: String? = nil) {
        self.host = host
        self.port = port
        self.database = database
        self.user = user
        self.password = password
        self.sslMode = sslMode
    }
}

/// OAuth 2.0 token pair. Refresh-token is optional because some flows
/// only return an access token; `expiresAt` is the access-token expiry
/// in wall-clock time so callers can compare against `Date()` without
/// needing to track issued-at separately.
public struct OAuthPair: Codable, Equatable, Sendable {
    public let accessToken: String
    public let refreshToken: String?
    public let scope: String?
    public let expiresAt: Date

    public init(accessToken: String, refreshToken: String?, scope: String?, expiresAt: Date) {
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.scope = scope
        self.expiresAt = expiresAt
    }
}

/// Generic connection-fields bundle for credential shapes that don't
/// fit `DBCredentials` or `OAuthPair` — e.g. AWS IAM
/// (access-key-id + secret + region + optional session-token), SMTP
/// (host + port + username + password + tls), API keys with
/// associated metadata.
///
/// The `kind` field is a free-form discriminator (`"aws-iam"`,
/// `"smtp"`, `"api-key"`, etc.) so consumers can dispatch on it.
/// Field names are caller-specific — broker stores them as-is from
/// the vault entry, no schema enforcement at the protocol layer.
public struct ConnectionBundle: Codable, Equatable, Sendable {
    public let kind: String
    public let fields: [String: String]
    /// Optional expiry timestamp for connection bundles whose contents
    /// rotate (e.g. AWS STS session tokens). nil = no automatic expiry.
    public let expiresAt: Date?

    public init(kind: String, fields: [String: String], expiresAt: Date? = nil) {
        self.kind = kind
        self.fields = fields
        self.expiresAt = expiresAt
    }
}
