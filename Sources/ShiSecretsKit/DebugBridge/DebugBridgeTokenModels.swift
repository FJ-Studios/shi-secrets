// DebugBridgeTokenModels.swift — W7 KatagamiDebugBridge token types
//
// JWT claim structure and issuance/revocation models for the debug bridge
// OAuth2 client_credentials flow.
//
// Operator ballot 2026-05-25:
//   OQ-KDBR-01: YES codesign check SH7MZH647S (enforced in bridge, not here)
//   OQ-KDBR-02: SPKI CA pin (enforced in bridge TLS layer)
//   OQ-KDBR-03: Tailscale default bind (enforced in bridge)
//   OQ-KDBR-04: YES rate-limit 10 failed /revocation/check / 5min (enforced in broker HTTP)
//
// Credential storage rule ([[feedback_no-credentials-in-env-vars]]):
//   - client_id + client_secret: macOS Keychain (Security.framework)
//   - Bearer token: in-process actor only (BridgeTokenCache in KatagamiDebugBridge)
//   - NEVER: env vars, flat files, /tmp, Postgres column

import Foundation

// MARK: - Scope

/// Scopes that can be granted to a KatagamiDebugBridge token.
public struct DebugBridgeScope: OptionSet, Sendable, Hashable {
    public let rawValue: Int
    public init(rawValue: Int) { self.rawValue = rawValue }

    /// Read view hierarchy, properties (non-mutating).
    public static let read    = DebugBridgeScope(rawValue: 1 << 0)
    /// Inspect live component state.
    public static let inspect = DebugBridgeScope(rawValue: 1 << 1)
    /// Capture snapshot (screenshot / render).
    public static let snap    = DebugBridgeScope(rawValue: 1 << 2)
    /// Mutate a component property (privileged).
    public static let rebind  = DebugBridgeScope(rawValue: 1 << 3)

    public static let all: DebugBridgeScope = [.read, .inspect, .snap, .rebind]

    /// Parse space-separated scope string from JWT claim.
    public static func parse(_ raw: String) -> DebugBridgeScope {
        var result: DebugBridgeScope = []
        for part in raw.split(separator: " ") {
            switch part {
            case "read":    result.insert(.read)
            case "inspect": result.insert(.inspect)
            case "snap":    result.insert(.snap)
            case "rebind":  result.insert(.rebind)
            default: break
            }
        }
        return result
    }

    /// Emit space-separated scope string for JWT claim.
    public var scopeString: String {
        var parts: [String] = []
        if contains(.read)    { parts.append("read") }
        if contains(.inspect) { parts.append("inspect") }
        if contains(.snap)    { parts.append("snap") }
        if contains(.rebind)  { parts.append("rebind") }
        return parts.joined(separator: " ")
    }
}

// MARK: - JWT Claims

/// Claims present in a KatagamiDebugBridge JWT.
/// Audience is always ["KatagamiDebugBridge"] — bridge rejects tokens with wrong aud.
public struct DebugBridgeClaims: Sendable, Codable, Hashable {
    public let sub:       String            // operator-id (PocketBase user UUID)
    public let aud:       [String]          // must contain "KatagamiDebugBridge"
    public let exp:       Int               // unix epoch; max issued_at + 86400
    public let scope:     String            // space-separated DebugBridgeScope
    public let kid:       String            // signing key UUID v4
    public let jti:       String            // UUID v4 per token (revocation + replay)
    public let iat:       Int               // issued-at unix epoch
    public let device_id: String?          // SHA-256 of hardware UUID (optional)

    public var parsedScope: DebugBridgeScope { .parse(scope) }

    public var isExpired: Bool {
        Int(Date().timeIntervalSince1970) > exp
    }

    /// Maximum allowed clock drift between iat and now (±30s).
    public static let clockDriftTolerance: Int = 30

    public var isFresh: Bool {
        let now = Int(Date().timeIntervalSince1970)
        return abs(now - iat) <= Self.clockDriftTolerance
    }
}

// MARK: - Token Issuance Request / Response

/// POST /oauth2/token request body for client_credentials grant.
public struct DebugBridgeTokenRequest: Sendable, Encodable {
    public let grant_type:  String = "client_credentials"
    public let audience:    String = "KatagamiDebugBridge"
    public let scope:       String
    public let device_id:   String?
    public let client_id:   String
    // client_secret is passed via HTTP Basic Auth header, not body
    // (per OAuth2 client_credentials spec — secret never in JSON body)

    public init(scope: DebugBridgeScope, device_id: String?, client_id: String) {
        self.scope     = scope.scopeString
        self.device_id = device_id
        self.client_id = client_id
    }
}

/// POST /oauth2/token successful response.
public struct DebugBridgeTokenResponse: Sendable, Decodable {
    public let access_token: String   // signed JWT
    public let token_type:   String   // "Bearer"
    public let expires_in:   Int      // seconds until exp
    public let scope:         String
}

// MARK: - Revocation

/// POST /debug-bridge/revoke request.
public struct DebugBridgeRevokeRequest: Sendable, Encodable {
    public enum Target: Sendable, Encodable {
        case jti(String)
        case device(String)
        case all

        private enum CodingKeys: String, CodingKey {
            case mode, jti, device_id
        }
        public func encode(to encoder: Encoder) throws {
            var c = encoder.container(keyedBy: CodingKeys.self)
            switch self {
            case .jti(let j):    try c.encode("jti",    forKey: .mode); try c.encode(j, forKey: .jti)
            case .device(let d): try c.encode("device", forKey: .mode); try c.encode(d, forKey: .device_id)
            case .all:           try c.encode("all",    forKey: .mode)
            }
        }
    }
    public let target:      Target
    public let revoked_by:  String  // "operator:<sub>"
    public let reason:      String?

    public init(target: Target, revoked_by: String, reason: String? = nil) {
        self.target = target
        self.revoked_by = revoked_by
        self.reason = reason
    }
}

// MARK: - Revocation Check

/// GET /revocation/check?jti=<jti> response.
public struct DebugBridgeRevocationCheckResponse: Sendable, Decodable {
    public let jti:      String
    public let revoked:  Bool
    public let revoked_at: String?  // ISO8601 if revoked
}

// MARK: - JWKS

/// GET /.well-known/jwks.json — JSON Web Key Set (RFC 7517).
public struct DebugBridgeJWKS: Sendable, Decodable {
    public struct JWK: Sendable, Decodable {
        public let kty:    String   // "OKP"
        public let crv:    String   // "Ed25519"
        public let kid:    String   // key UUID
        public let x:      String   // base64url-encoded public key
        public let status: String   // "active" | "grace"
    }
    public let keys: [JWK]
}

// MARK: - Key Rotation / Compromise

public struct DebugBridgeKeyRotateResponse: Sendable, Decodable {
    public let kid_new:       String
    public let kid_old:       String
    public let grace_ends_at: String  // ISO8601
}

public struct DebugBridgeKeyCompromiseResponse: Sendable, Decodable {
    public let kid_compromised:  String
    public let kid_new:          String
    public let tokens_revoked:   Int
    public let completed_at:     String  // ISO8601; target < 5min from command
}
