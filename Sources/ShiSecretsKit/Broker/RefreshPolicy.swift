import Foundation

// RefreshPolicy — consumer-kind → TTL / refresh-before-dies / revocation-SLA
// mapping.
//
// Phase 0.3a (BR-G-09) of features/shikkisecrets-broker-completion.md.
//
// `RotationIntervals` ships TICK constants (hot=300s, warm=1800s, etc.)
// for the rotation engine itself. BR-G-09 surfaced a different gap:
// a long-lived caller (MCP server, shi daemon, PostgresPool) holding
// an ephemeral token / connection bundle needs a policy that tells it
// (1) when to refresh BEFORE the credential dies, and (2) how long to
// wait for a revocation message to arrive after the broker issues one.
// A bare TTL is insufficient — by the time TTL expires the long-lived
// process has already failed mid-request.
//
// This file ships the type vocabulary. The actual policy values per
// consumer-kind get tuned in ops review and lived inside the daemon's
// dispatch handler (Phase 0.3b).

/// Identifies the calling-pattern category. The broker uses this to
/// pick a `RefreshPolicy` from a per-kind table; the client uses it to
/// label its sessions so audit can attribute usage.
public enum ConsumerKind: String, Codable, Equatable, Sendable, CaseIterable {
    /// One-shot CLI invocation (`shi secret get foo`) — token used
    /// once and discarded. Short TTL is fine.
    case interactive
    /// Long-running daemon (shikki-secrets-brokerd's own clients,
    /// shi flow runner). Needs refresh-before-dies + tight revocation SLA.
    case daemon
    /// MCP server (Claude / agent traffic). LLM-context-touched per
    /// `BR-A-03 llm_touched` — tighter TTL than `daemon` and forced
    /// rotation when conversation ends.
    case mcpServer
    /// Anything else with a multi-hour lifetime (Vapor app server
    /// reading a Postgres pool credential). Mid-TTL + medium SLA.
    case longLived
}

/// How aggressively the broker + client should refresh and how fast
/// the client must react to a revocation message.
///
/// Wire-Codable so the broker can ship the policy alongside the
/// credential — caller doesn't need to know the per-kind table.
public struct RefreshPolicy: Codable, Equatable, Sendable {
    /// Hard TTL — caller MUST stop using the credential after this
    /// many seconds since issuance. Server enforces by rejecting
    /// requests using stale jti.
    public let ttlSeconds: Int
    /// Caller SHOULD refresh when (ttl - elapsed) <= refreshBeforeSeconds.
    /// Defaults to half-life for `daemon`, 25% of TTL for `longLived`,
    /// 0 (no preemptive refresh) for `interactive`.
    public let refreshBeforeSeconds: Int
    /// Maximum acceptable lag between broker emitting a revocation
    /// event (NATS: `shikki.secrets.revoked.<jti>`) and the caller
    /// honoring it. Beyond this SLA, broker's audit row flags the
    /// caller as `revocation_lagged`.
    public let revocationSLAMSeconds: Int

    public init(ttlSeconds: Int, refreshBeforeSeconds: Int, revocationSLAMSeconds: Int) {
        self.ttlSeconds = ttlSeconds
        self.refreshBeforeSeconds = refreshBeforeSeconds
        self.revocationSLAMSeconds = revocationSLAMSeconds
    }

    // MARK: - Per-kind defaults

    /// Tunable defaults per consumer-kind. Operators override per-
    /// deployment via `~/.shikki/config/broker.toml` in a future spec;
    /// these values are the reasonable starting point baked into the
    /// type so consumers can ship without an explicit config file.
    public static func defaultPolicy(for kind: ConsumerKind) -> RefreshPolicy {
        switch kind {
        case .interactive:
            // Short TTL, no preemptive refresh — one-shot use, then
            // the CLI exits and the token is discarded.
            return RefreshPolicy(
                ttlSeconds: 300,        // 5 min hard cap
                refreshBeforeSeconds: 0,
                revocationSLAMSeconds: 1_000   // 1s revocation lag tolerance
            )
        case .daemon:
            // 1h TTL, refresh at 30min, sub-second revocation SLA.
            return RefreshPolicy(
                ttlSeconds: 3_600,
                refreshBeforeSeconds: 1_800,
                revocationSLAMSeconds: 500
            )
        case .mcpServer:
            // Per BR-A-03: MCP-transport TTL capped at 600s.
            // Refresh at 5min mark; tightest revocation SLA because
            // any token-touched-by-LLM is compromised-on-leak.
            return RefreshPolicy(
                ttlSeconds: 600,
                refreshBeforeSeconds: 300,
                revocationSLAMSeconds: 200
            )
        case .longLived:
            // Vapor app servers, Postgres pools — multi-hour life.
            // TTL = 4h, refresh at 75% mark, medium SLA.
            return RefreshPolicy(
                ttlSeconds: 14_400,
                refreshBeforeSeconds: 3_600,
                revocationSLAMSeconds: 2_000
            )
        }
    }
}
