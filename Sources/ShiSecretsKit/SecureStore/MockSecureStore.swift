// MockSecureStore — in-memory SecureStore for tests.
//
// W2 of spec e8c4a921-7d3b-4f5e-9a2c-1d6b8f4e3a91
// Panel #2 verdict: MockSecureStore lives in the main ShiSecretsKit target
// (not only the test target) so it can be used both by ShiSecretsBrokerdTests
// AND by ShiSecretsKitTests without circular imports.
//
// Contract: zero Keychain/OS calls — pure in-memory dict, isolated by actor.
// NOT for production use. Actor isolation ensures thread-safety in async tests.
//
// See: super-challenge-w2-cross-platform-secure-cache-2026-06-24.md §6

import Foundation

// MARK: - MockSecureStore

/// In-memory `SecureStore` implementation for tests.
///
/// Stores data in a plain `[String: Data]` dictionary keyed by
/// `"<service>:<account>"`. No OS interactions whatsoever.
///
/// - Note: `throwOnWrite` and `throwOnRead` allow tests to simulate
///   Keychain failure paths (e.g. t05, t06 in VaultwardenClientTokenCacheTests).
public actor MockSecureStore: SecureStore {

    // MARK: - State

    private var store: [String: Data] = [:]

    /// When set, `write(_:service:account:)` throws this error.
    public private(set) var throwOnWrite: SecureStoreError? = nil

    /// When set, `read(service:account:)` throws this error.
    public private(set) var throwOnRead: SecureStoreError? = nil

    /// Set the error to throw on write (must be called from within the actor context — use `await`).
    public func setThrowOnWrite(_ error: SecureStoreError?) {
        throwOnWrite = error
    }

    /// Set the error to throw on read (must be called from within the actor context — use `await`).
    public func setThrowOnRead(_ error: SecureStoreError?) {
        throwOnRead = error
    }

    // MARK: - Init

    /// Create an empty mock store.
    public init() {}

    /// Create a pre-seeded mock store.
    /// - Parameter initialEntries: Dictionary of `"<service>:<account>"` → `Data`.
    public init(initialEntries: [String: Data]) {
        self.store = initialEntries
    }

    // MARK: - SecureStore conformance

    public func read(service: String, account: String) async throws -> Data? {
        if let err = throwOnRead { throw err }
        return store[key(service: service, account: account)]
    }

    public func write(_ data: Data, service: String, account: String) async throws {
        if let err = throwOnWrite { throw err }
        store[key(service: service, account: account)] = data
    }

    public func delete(service: String, account: String) async throws {
        store.removeValue(forKey: key(service: service, account: account))
    }

    // MARK: - Test helpers

    /// Returns the number of entries currently held.
    public var count: Int { store.count }

    /// Direct access to stored data for assertions (bypasses error injection).
    public func rawRead(service: String, account: String) -> Data? {
        store[key(service: service, account: account)]
    }

    // MARK: - Private

    private func key(service: String, account: String) -> String {
        "\(service):\(account)"
    }
}
