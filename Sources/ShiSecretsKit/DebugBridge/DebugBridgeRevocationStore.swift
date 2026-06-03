// DebugBridgeRevocationStore.swift — W7 KatagamiDebugBridge revocation
//
// In-memory + Postgres-backed revocation store for the shi-secrets broker.
// Loaded from debug_bridge_revoked_tokens on startup; updated on each revoke.
// Provides O(1) revocation check for /revocation/check endpoint.
//
// Rate-limiting (OQ-KDBR-04): 10 failed /revocation/check responses from
// the same source IP in 5 minutes → 60s temporary block + audit alert.

import Foundation

// MARK: - Revocation Store

/// Actor-isolated in-memory revocation set backed by Postgres.
/// Broker loads the full set at startup via `loadFromDB()`.
/// Bridge queries via `GET /revocation/check?jti=<jti>` which calls `isRevoked(_:)`.
public actor DebugBridgeRevocationStore {

    private var revokedJTIs: Set<String> = []

    // MARK: Query

    /// O(1) revocation check. Called by /revocation/check HTTP handler.
    public func isRevoked(_ jti: String) -> Bool {
        revokedJTIs.contains(jti)
    }

    // MARK: Mutations

    /// Insert a single jti into the revocation set (and Postgres).
    /// Called by `shi debug-bridge revoke <jti>`.
    public func revoke(jti: String) {
        revokedJTIs.insert(jti)
        // Postgres insert is done by the HTTP handler before calling this;
        // this is the in-memory update for the in-process broker.
    }

    /// Mass-revoke all jti values for a given kid.
    /// Called by `shi debug-bridge key-compromise`.
    /// Returns the count of revoked tokens.
    public func massRevoke(jtisForKid: [String]) -> Int {
        for jti in jtisForKid { revokedJTIs.insert(jti) }
        return jtisForKid.count
    }

    /// Load full revocation set from Postgres on broker startup.
    public func loadFromDB(jtis: [String]) {
        revokedJTIs = Set(jtis)
    }
}

// MARK: - Rate Limiter (OQ-KDBR-04)

/// Per-source-IP rate limiter for /revocation/check failures.
/// 10 failed responses from the same IP in 5 minutes → 60s temporary block
/// + audit alert event (rate_limit_block).
///
/// Storage: fully in-memory (actor-isolated). No DB persistence —
/// broker restart resets rate limit counters (acceptable; attacker must
/// re-establish network access after broker restart anyway).
public actor DebugBridgeRateLimiter {

    public static let maxFailures:     Int       = 10
    public static let windowSeconds:   TimeInterval = 5 * 60   // 5 minutes
    public static let blockSeconds:    TimeInterval = 60        // 60s temp block

    private struct Window {
        var failures:    [Date] = []
        var blockedUntil: Date? = nil
    }

    private var windows: [String: Window] = [:]  // keyed by IP string

    // MARK: Check + Record

    public enum CheckResult: Sendable {
        case allowed
        case blocked(until: Date)
    }

    /// Call BEFORE processing a /revocation/check that returned a failure (token not found / revoked).
    /// Returns `.blocked` if this IP has exceeded the rate limit.
    public func recordFailure(ip: String, at now: Date = Date()) -> CheckResult {
        evictStale(ip: ip, now: now)
        if let until = windows[ip]?.blockedUntil, until > now {
            return .blocked(until: until)
        }
        windows[ip, default: Window()].failures.append(now)
        let count = windows[ip]?.failures.count ?? 0
        if count >= Self.maxFailures {
            let until = now.addingTimeInterval(Self.blockSeconds)
            windows[ip]?.blockedUntil = until
            windows[ip]?.failures = []  // reset window after block
            return .blocked(until: until)
        }
        return .allowed
    }

    /// Check if an IP is currently blocked (call BEFORE processing the request).
    public func isBlocked(ip: String, at now: Date = Date()) -> Bool {
        guard let until = windows[ip]?.blockedUntil else { return false }
        return until > now
    }

    // MARK: Housekeeping

    private func evictStale(ip: String, now: Date) {
        let cutoff = now.addingTimeInterval(-Self.windowSeconds)
        windows[ip]?.failures.removeAll { $0 < cutoff }
        if let until = windows[ip]?.blockedUntil, until <= now {
            windows[ip]?.blockedUntil = nil
        }
    }
}

// MARK: - Signing Key Registry

/// In-memory signing key set for JWKS. Backed by debug_bridge_signing_keys table.
/// Supports dual-kid (active + grace) for key rotation.
public actor DebugBridgeSigningKeyRegistry {

    public struct KeyEntry: Sendable {
        public let kid:          String
        public let publicKeyHex: String  // 32-byte Ed25519 public key, hex-encoded
        public let status:       KeyStatus
        public let issuedAt:     Date
        public let retiredAt:    Date?
    }

    public enum KeyStatus: String, Sendable {
        case active, grace, retired, compromised
    }

    private var keys: [String: KeyEntry] = [:]

    // MARK: Query

    public func publicKey(for kid: String) -> KeyEntry? { keys[kid] }

    public func activeKeys() -> [KeyEntry] {
        keys.values.filter { $0.status == .active || $0.status == .grace }
    }

    public var currentKid: String? {
        keys.values.first(where: { $0.status == .active })?.kid
    }

    // MARK: Mutations

    public func insert(_ entry: KeyEntry) { keys[entry.kid] = entry }

    public func transition(kid: String, to status: KeyStatus, retiredAt: Date? = nil) {
        guard var entry = keys[kid] else { return }
        entry = KeyEntry(
            kid: entry.kid,
            publicKeyHex: entry.publicKeyHex,
            status: status,
            issuedAt: entry.issuedAt,
            retiredAt: retiredAt
        )
        keys[kid] = entry
    }

    public func loadFromDB(entries: [KeyEntry]) {
        for entry in entries { keys[entry.kid] = entry }
    }
}
