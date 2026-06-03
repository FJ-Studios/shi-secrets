import Foundation

// SelfRevokeWatcher — discovery-token exception monitor (BR-E-05, BR-E-06).
//
// A narrow subset of tokens (scope depth ≥ 2, ttl ≤ 600s, op=read) can be
// issued with `self_revoke_declared=true`: they promise to call the
// broker's revoke endpoint before `dies_at`. If they don't, the watcher
// emits an `AnomalySignal.selfRevokeMissed` + writes a seams row +
// queues the parent secret for rotation.
//
// Wave 3 shape: an actor that tracks `(jti → parent secret, diesAt)`
// and exposes `tick(now:)` the ConversationSweepJob / kernel integration
// calls periodically. The broker's request handler (Wave 4) will call
// `watch(jti:secret:diesAt:)` whenever it mints a self-revoking discovery
// token; the registry's `revoke(jti:)` is checked here to see whether
// the self-revoke call actually landed.

public actor SelfRevokeWatcher {

    public static let maxDiscoveryTTL: Int = 600
    public static let minScopeDepth: Int = 2

    public struct Entry: Sendable, Equatable {
        public let jti: String
        public let parentSecret: String
        public let scope: String
        public let ttl: Int
        public let op: ShikkiSBT.Op
        public let diesAt: Date
    }

    public enum WatchError: Swift.Error, Sendable, Equatable {
        case tooBroadScope(depth: Int)
        case ttlTooLong(seconds: Int)
        case opNotRead(op: ShikkiSBT.Op)
    }

    private let registry: TokenRegistry
    private let seams: SeamsWriter
    private let engine: RotationEngine
    private var tracked: [String: Entry] = [:]

    public init(
        registry: TokenRegistry,
        seams: SeamsWriter,
        engine: RotationEngine
    ) {
        self.registry = registry
        self.seams = seams
        self.engine = engine
    }

    /// Accept a narrow discovery token into the watcher's book. Rejects
    /// broad-scope, long-TTL, or write-op tokens — these must go through
    /// the ordinary broker path with full audit + dies_at ceiling.
    public func watch(entry: Entry) throws {
        let depth = Self.scopeDepth(entry.scope)
        guard depth >= Self.minScopeDepth else {
            throw WatchError.tooBroadScope(depth: depth)
        }
        guard entry.ttl <= Self.maxDiscoveryTTL else {
            throw WatchError.ttlTooLong(seconds: entry.ttl)
        }
        guard entry.op == .read else {
            throw WatchError.opNotRead(op: entry.op)
        }
        tracked[entry.jti] = entry
    }

    /// Observability accessor — returns the list of currently-tracked jtis.
    public func tracking() -> [Entry] { Array(tracked.values) }

    /// Sweep: for every tracked entry whose diesAt has passed, check
    /// whether the token was revoked (self-revoke call landed). If NOT,
    /// emit anomaly + seams row + queue parent rotation.
    public func tick(now: Date) async throws {
        for (jti, entry) in tracked where entry.diesAt <= now {
            let revoked = await registry.isRevoked(jti: jti)
            if !revoked {
                let signal = AnomalySignal.selfRevokeMissed(jti: jti, secretName: entry.parentSecret)
                try await seams.append(
                    signal: signal,
                    secret: entry.parentSecret,
                    outcome: .bypassed,
                    ts: now,
                    notes: "self-revoke not called before dies_at (jti=\(jti))"
                )
                try await engine.onAnomaly(signal, secretName: entry.parentSecret)
            }
            tracked.removeValue(forKey: jti)
        }
    }

    /// Glob depth — `ovh/fr/zone1` → 3, `ovh/*` → 2, `*` → 1.
    private static func scopeDepth(_ scope: String) -> Int {
        scope.split(separator: "/").count
    }
}
