import Foundation

// InMemoryCache — ephemeral TTL cache for resolved secret values.
//
// BR-SSEC-03: TTL = 30s, in-memory only. NEVER written to disk per
// [[container-secrets-no-file-residency]]. Actor-isolated so concurrent
// callers do not race on the internal dictionary.
//
// CRIT-3 fix: entries now store a JTI alongside the value. On every cache
// hit, `isRevoked` is consulted — a stale hit on a revoked token returns
// nil and evicts the entry. `invalidateAll()` is called by rotation +
// revokeAllBots paths.
//
// W1 of features/shi-secrets-uri-scheme-and-plugin-extraction-2026-05-31.md.

/// An in-memory TTL cache for `ShiSecretURI` → `SecretValue` mappings.
///
/// - All state is ephemeral; no file I/O is performed.
/// - Default TTL is 30 seconds per BR-SSEC-03.
/// - CRIT-3: every entry carries its JTI; hits are revocation-checked.
public actor InMemoryCache {

    // MARK: - Types

    /// A secret value returned by the resolver backend.
    public struct SecretValue: Sendable, Equatable {
        public let plaintext: String
        /// CRIT-3: the JTI of the ephemeral token used to resolve this value.
        public let jti: String
        public init(plaintext: String, jti: String) {
            self.plaintext = plaintext
            self.jti = jti
        }
        /// Backward-compat init for tests that don't supply a JTI — uses a random sentinel.
        public init(plaintext: String) {
            self.plaintext = plaintext
            self.jti = "cache-\(UUID().uuidString)"
        }
    }

    private struct Entry {
        let value: SecretValue
        let expiresAt: Date
    }

    // MARK: - Configuration

    /// Default TTL: 30 seconds per BR-SSEC-03.
    public static let defaultTTL: TimeInterval = 30

    // MARK: - State

    private var store: [ShiSecretURI: Entry] = [:]
    private let ttl: TimeInterval
    private let clock: () -> Date
    /// CRIT-3: revocation check; nil = revocation disabled (tests that don't supply a registry).
    private let isRevoked: (@Sendable (String) -> Bool)?

    // MARK: - Init

    /// Creates a cache with the given TTL and clock function.
    ///
    /// - Parameters:
    ///   - ttl: Time-to-live for each entry. Defaults to `InMemoryCache.defaultTTL`.
    ///   - clock: Provider of the current date; injected for test control.
    ///   - isRevoked: CRIT-3 — called on every cache hit with the entry's JTI.
    ///     Return true to treat the cached entry as revoked (evicts + returns nil).
    public init(
        ttl: TimeInterval = InMemoryCache.defaultTTL,
        clock: @escaping @Sendable () -> Date = { Date() },
        isRevoked: (@Sendable (String) -> Bool)? = nil
    ) {
        self.ttl = ttl
        self.clock = clock
        self.isRevoked = isRevoked
    }

    // MARK: - Cache operations

    /// Returns the cached value for `uri` if it exists, has not expired,
    /// and its JTI has not been revoked; otherwise returns `nil`.
    public func get(_ uri: ShiSecretURI) -> SecretValue? {
        guard let entry = store[uri] else { return nil }
        if clock() >= entry.expiresAt {
            store.removeValue(forKey: uri)
            return nil
        }
        // CRIT-3: evict on revocation.
        if let check = isRevoked, check(entry.value.jti) {
            store.removeValue(forKey: uri)
            return nil
        }
        return entry.value
    }

    /// Stores `value` for `uri` with a TTL from the current clock time.
    public func set(_ uri: ShiSecretURI, _ value: SecretValue) {
        let expiresAt = clock().addingTimeInterval(ttl)
        store[uri] = Entry(value: value, expiresAt: expiresAt)
    }

    /// Removes the cached entry for `uri`, if present.
    public func invalidate(_ uri: ShiSecretURI) {
        store.removeValue(forKey: uri)
    }

    /// CRIT-3: invalidate ALL entries — called on rotation and revokeAllBots.
    public func invalidateAll() {
        store.removeAll()
    }

    /// Removes all expired entries. Called opportunistically; the cache
    /// is also lazy-evicted in `get(_:)`.
    public func evictExpired() {
        let now = clock()
        store = store.filter { $0.value.expiresAt > now }
    }

    /// Number of currently stored entries (may include expired ones not yet
    /// evicted by `evictExpired()`; use for testing only).
    public func count() -> Int {
        store.count
    }
}
