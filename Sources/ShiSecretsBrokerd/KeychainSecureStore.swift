// KeychainSecureStore — macOS Keychain implementation of SecureStore.
//
// W2 of spec e8c4a921-7d3b-4f5e-9a2c-1d6b8f4e3a91
// Panel #1 verdict (D8F2F0FCD05E484FBF56115911DE04C2): Option C — macOS Keychain.
// Panel #2 verdict (98E8F902577B4558A2A08F22F4EC3E8B): SecureStore protocol DI.
//
// Security attributes (panel #1 ratified):
//   kSecAttrAccessible = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
//     → Survives screen lock (brokerd can refresh tokens without user present)
//     → Does NOT sync to iCloud Keychain (device-bound)
//     → Excluded from Time Machine by Apple policy (~/Library/Keychains/ is
//       in the hardcoded TimeMachineExclusions list — confirmed by Ronin Crit-R1)
//   kSecAttrSynchronizable = false
//     → No iCloud Keychain leakage across devices (T-W2-K02)
//
// Linux: KernelKeyringSecureStore is W2.5 (deferred). A compilation stub that
// throws SecureStoreError.platformUnsupported is provided below so Linux CI
// compiles without error while the real implementation is pending.
//
// See: super-challenge-w2-token-cache-disk-safety-2026-06-24.md §6
//      super-challenge-w2-cross-platform-secure-cache-2026-06-24.md §6

import Foundation
import ShiSecretsKit

#if os(macOS)
import Security

// MARK: - KeychainSecureStore (macOS)

/// macOS Keychain-backed `SecureStore`.
///
/// Uses `kSecClassGenericPassword` items with:
/// - `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` — survives screen lock,
///   not backed up to iCloud or Time Machine.
/// - `kSecAttrSynchronizable = false` — device-bound, no cross-device leakage.
///
/// On write: tries `SecItemAdd`; if `errSecDuplicateItem`, falls through to
/// `SecItemUpdate` so callers can use `write` idempotently.
/// On delete: `errSecItemNotFound` is silently ignored (no-op per protocol).
public actor KeychainSecureStore: SecureStore {

    public init() {}

    // MARK: - SecureStore

    public func read(service: String, account: String) async throws -> Data? {
        let query: [CFString: Any] = [
            kSecClass:           kSecClassGenericPassword,
            kSecAttrService:     service,
            kSecAttrAccount:     account,
            kSecReturnData:      true,
            kSecMatchLimit:      kSecMatchLimitOne,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data else {
                throw SecureStoreError.malformedData
            }
            return data
        case errSecItemNotFound:
            return nil
        default:
            throw SecureStoreError.osStatus(status)
        }
    }

    public func write(_ data: Data, service: String, account: String) async throws {
        let attributes: [CFString: Any] = [
            kSecClass:           kSecClassGenericPassword,
            kSecAttrService:     service,
            kSecAttrAccount:     account,
            kSecValueData:       data,
            // AfterFirstUnlock: brokerd (LaunchAgent) runs while screen is locked
            // after first login; WhenUnlocked would block it.
            kSecAttrAccessible:  kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            // Synchronizable = false → no iCloud Keychain; device-bound only.
            kSecAttrSynchronizable: false,
        ]
        var status = SecItemAdd(attributes as CFDictionary, nil)
        if status == errSecDuplicateItem {
            // Item exists — update the value in-place.
            let query: [CFString: Any] = [
                kSecClass:       kSecClassGenericPassword,
                kSecAttrService: service,
                kSecAttrAccount: account,
            ]
            let update: [CFString: Any] = [
                kSecValueData:   data,
            ]
            status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        }
        guard status == errSecSuccess else {
            throw SecureStoreError.osStatus(status)
        }
    }

    public func delete(service: String, account: String) async throws {
        let query: [CFString: Any] = [
            kSecClass:       kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
        ]
        let status = SecItemDelete(query as CFDictionary)
        // errSecItemNotFound is acceptable — delete is a no-op if absent.
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SecureStoreError.osStatus(status)
        }
    }
}

#elseif os(Linux)

// MARK: - Linux stub (W2.5 — deferred until first Linux shikki node)

/// Linux stub for `SecureStore`. Throws `SecureStoreError.platformUnsupported`
/// on every call. The real `KernelKeyringSecureStore` implementation (W2.5)
/// will replace this once a Linux deployment target exists.
///
/// Rationale (panel #2 unanimous): shipping a stub without real integration tests
/// on the target kernel would be a [[no-naked-checkmark]] anti-pattern.
/// W2.5 gates on first Linux node deployment.
public actor KeychainSecureStore: SecureStore {

    public init() {}

    public func read(service: String, account: String) async throws -> Data? {
        throw SecureStoreError.platformUnsupported
    }

    public func write(_ data: Data, service: String, account: String) async throws {
        throw SecureStoreError.platformUnsupported
    }

    public func delete(service: String, account: String) async throws {
        throw SecureStoreError.platformUnsupported
    }
}

#endif
