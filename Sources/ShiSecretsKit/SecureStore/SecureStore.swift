// SecureStore — cross-platform protocol for secret storage.
//
// W2 of spec e8c4a921-7d3b-4f5e-9a2c-1d6b8f4e3a91
// Panel #2 verdict (98E8F902577B4558A2A08F22F4EC3E8B): SecureStore protocol
// MUST be defined at this layer (ShiSecretsKit — platform-agnostic) so that
// VaultwardenTokenCache is also platform-agnostic.
//
// Platform-specific implementations live in ShiSecretsBrokerd:
//   - KeychainSecureStore  (macOS — W2, this wave)
//   - KernelKeyringSecureStore (Linux — W2.5, deferred until first Linux node)
//
// Mock for tests: MockSecureStore (same file, both platforms, in-memory dict).
//
// See: super-challenge-w2-cross-platform-secure-cache-2026-06-24.md §6

import Foundation

// MARK: - SecureStore protocol

/// A cross-platform actor-based protocol for reading, writing, and deleting
/// secrets. Implementations:
///   - `KeychainSecureStore` (macOS Keychain, W2)
///   - `KernelKeyringSecureStore` (Linux kernel keyring, W2.5 — deferred)
///   - `MockSecureStore` (in-memory, test injection only)
///
/// All methods are async + throwing so callers can await across actor
/// boundaries without blocking.
public protocol SecureStore: Actor {
    /// Read secret bytes. Returns `nil` if the entry does not exist.
    func read(service: String, account: String) async throws -> Data?

    /// Write or update secret bytes for the given service+account pair.
    func write(_ data: Data, service: String, account: String) async throws

    /// Delete the secret. No-op (does NOT throw) if the entry is not found.
    func delete(service: String, account: String) async throws
}

// MARK: - SecureStoreError

/// Errors surfaced by `SecureStore` implementations.
public enum SecureStoreError: Error, Sendable {
    /// macOS Security framework returned a non-success OSStatus.
    case osStatus(Int32)

    /// The current platform does not have a `SecureStore` implementation.
    /// On Linux this is thrown by the W2.5 stub until KernelKeyringSecureStore
    /// is implemented and deployed.
    case platformUnsupported

    /// The stored data could not be decoded into the expected format.
    case malformedData
}
