import Foundation

// BrokerResponse — type-system-enforced "no long-lived plaintext" gate
// (Task 34 — BR-H-01).
//
// The broker's public reply surface has exactly three cases:
//   .ephemeralToken(ShikkiSBT)        — MCP + any llm_touched path
//   .boundPlaintext(jti, plaintext)   — local unix path; plaintext bound
//                                       to a specific short-lived jti
//   .deny(DenyReason)                 — caller is refused
//
// There is NO `.rawPlaintext(String)` case. Re-introducing one is a
// breaking change that would trip every call-site switch; a future
// reviewer would notice immediately. This is the type-system half of
// BR-H-01; the behavioral half lives in the MCPBridge (Wave 4) which
// refuses to ever select `.boundPlaintext`.

public enum BrokerResponse: Sendable {
    /// The usual path — broker returns a signed ephemeral token. TTL
    /// is capped at 3600s by ShikkiSBT.Claims.validate (BR-A-03) and
    /// further tightened to 600s on the MCP transport.
    case ephemeralToken(ShikkiSBT)

    /// Local unix caller with read-plaintext entitlement. The `jti` is
    /// the caller-side audit key; `plaintext` is bound to it (broker
    /// expects the caller to discard both together).
    case boundPlaintext(jti: String, plaintext: String)

    /// Phase 0.3a (BR-G-04) — typed DB credentials. A Postgres / MySQL
    /// caller gets named fields instead of parsing a string DSN.
    /// `jti` is the caller-side audit key; the policy controls
    /// refresh + revocation cadence.
    case dbCredentials(jti: String, credentials: DBCredentials, policy: RefreshPolicy)

    /// Phase 0.3a (BR-G-04) — OAuth access + refresh token pair.
    /// Same `jti` + `policy` contract.
    case oauthPair(jti: String, pair: OAuthPair, policy: RefreshPolicy)

    /// Phase 0.3a (BR-G-04) — generic connection-fields bundle
    /// (AWS IAM, SMTP, custom-API-key etc).
    case connectionBundle(jti: String, bundle: ConnectionBundle, policy: RefreshPolicy)

    /// Caller refused. Reason is the closed-set DenyReason so audit
    /// logs can never carry free-form strings (BR-G-04).
    case deny(AuditRow.DenyReason)
}
