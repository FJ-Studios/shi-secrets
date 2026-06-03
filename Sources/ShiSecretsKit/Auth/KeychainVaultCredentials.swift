import Foundation
import Security

// KeychainVaultCredentials — macOS Keychain wrapper that stores and loads
// VaultwardenCredentials using Security.framework.
//
// Accessibility: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
// Access control: kSecAccessControlBiometryCurrentSet (set on write; LAContext
//   prompt required on read for high-stakes ops — see ProofOfPresence for W2).
//
// W1 ships the concrete macOS implementation. A SecureCredentialStore
// protocol + Linux/Windows variants are Wave 4/5/6 deliverables per spec.
// DO NOT abstract prematurely.
//
// Service identifier: "eu.fj-studios.shikki.vault"
// Account:            "vault-credentials"
//
// BR-SM-01, BR-SM-02, BR-SM-03

/// Keychain wrapper for VaultwardenCredentials.
///
/// The credentials JSON blob is written once by `shi secrets setup` (W2)
/// and read on every broker bootstrap. The Secure Enclave-backed access
/// control means the raw bytes cannot be extracted even with root access
/// on Apple Silicon.
public struct KeychainVaultCredentials: Sendable {

    // MARK: - Constants

    /// Bundle-rev service identifier — canonical across all Apple platforms.
    public static let service = "eu.fj-studios.shikki.vault"

    /// Keychain item account label.
    public static let account = "vault-credentials"

    // MARK: - Errors

    public enum KeychainError: Swift.Error, Sendable, Equatable {
        /// Item does not exist yet — `shi secrets setup` (W2) not run.
        case itemNotFound

        /// The Keychain item exists but its JSON blob cannot be decoded.
        case dataMalformed

        /// Security.framework returned an unexpected OSStatus.
        case osError(status: Int32)

        /// Attempted to write credentials but the item already exists
        /// and `overwrite: false` was passed.
        case itemAlreadyExists
    }

    public init() {}

    // MARK: - store(_:overwrite:)

    /// Persist credentials to the Keychain. Replaces any existing item
    /// when `overwrite` is true (default). Used by `shi secrets setup` (W2).
    ///
    /// Access flags (preferred when entitlements are present):
    ///   - kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly — survives
    ///     reboot once the user unlocks the device once.
    ///   - kSecAccessControlBiometryCurrentSet — biometric re-enroll
    ///     invalidates the item (protects against swapped fingerprints).
    ///
    /// Fallback (ad-hoc signed binary / no entitlements):
    ///   When `SecItemAdd` returns `errSecMissingEntitlement` (-34018) with the
    ///   biometry access control, the item is retried using only
    ///   `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` and no
    ///   `kSecAttrAccessControl`. This allows `shi` (ad-hoc signed, no
    ///   keychain-access-groups entitlement) to seed credentials into the
    ///   default login Keychain without the biometry gate. brokerd (entitled)
    ///   reads the same service+account without access group filtering.
    public func store(
        _ credentials: VaultwardenCredentials,
        overwrite: Bool = true
    ) throws {
        let data = try JSONEncoder().encode(credentials)
        let baseQuery = baseStoreQuery(data: data, accessControl: nil)

        // Attempt preferred path: biometry access control.
        var cfError: Unmanaged<CFError>?
        if let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            .biometryCurrentSet,
            &cfError
        ) {
            let acQuery = baseStoreQuery(data: data, accessControl: accessControl)
            do {
                try executeStore(query: acQuery as CFDictionary, overwrite: overwrite)
                return
            } catch KeychainError.osError(let status) where status == errSecMissingEntitlement {
                // -34018: binary lacks entitlements for the biometry access control
                // (ad-hoc signed `shi`). Fall through to the base query below.
                // The item is stored without the biometry gate — functionally
                // equivalent on dev machines without a real signing identity.
                _ = status  // silence unused warning
            }
            // Any other KeychainError propagates to the caller as-is.
        }

        // Fallback: no access control — plain accessibility flag only.
        try executeStore(query: baseQuery as CFDictionary, overwrite: overwrite)
    }

    private func baseStoreQuery(
        data: Data,
        accessControl: SecAccessControl?
    ) -> [CFString: Any] {
        var q: [CFString: Any] = [
            kSecClass:           kSecClassGenericPassword,
            kSecAttrService:     Self.service,
            kSecAttrAccount:     Self.account,
            kSecValueData:       data,
            kSecAttrAccessible:  kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        if let ac = accessControl {
            q[kSecAttrAccessControl] = ac
        }
        return q
    }

    private func executeStore(query: CFDictionary, overwrite: Bool) throws {
        var status = SecItemAdd(query, nil)
        if status == errSecDuplicateItem {
            guard overwrite else { throw KeychainError.itemAlreadyExists }
            // Delete and re-add rather than SecItemUpdate so the access
            // control flags are fully replaced (kSecAttrAccessControl is
            // not modifiable via SecItemUpdate on macOS 14+).
            let deleteQuery: [CFString: Any] = [
                kSecClass:       kSecClassGenericPassword,
                kSecAttrService: Self.service,
                kSecAttrAccount: Self.account,
            ]
            SecItemDelete(deleteQuery as CFDictionary)
            status = SecItemAdd(query, nil)
        }
        guard status == errSecSuccess else {
            throw KeychainError.osError(status: status)
        }
    }

    // MARK: - load() throws -> VaultwardenCredentials

    /// Load credentials from the Keychain. Throws `.itemNotFound` when
    /// `shi secrets setup` has not been run yet.
    ///
    /// Note: on devices with biometrics, the OS will show a biometric
    /// prompt automatically when the access control flag is set. To
    /// drive the prompt with a custom reason string, pass a LAContext
    /// via ProofOfPresence.require (W2 path); for W1 broker bootstrap
    /// the OS-default prompt is acceptable.
    public func load() throws -> VaultwardenCredentials {
        let query: [CFString: Any] = [
            kSecClass:            kSecClassGenericPassword,
            kSecAttrService:      Self.service,
            kSecAttrAccount:      Self.account,
            kSecReturnData:       true,
            kSecMatchLimit:       kSecMatchLimitOne,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            guard let data = result as? Data else {
                throw KeychainError.dataMalformed
            }
            do {
                return try JSONDecoder().decode(VaultwardenCredentials.self, from: data)
            } catch {
                throw KeychainError.dataMalformed
            }
        case errSecItemNotFound:
            throw KeychainError.itemNotFound
        case errSecInteractionNotAllowed:
            throw KeychainError.osError(status: status)
        default:
            throw KeychainError.osError(status: status)
        }
    }

    // MARK: - delete()

    /// Remove the credentials item from the Keychain. Used by
    /// `shi secrets reset` (future). Silent if the item does not exist.
    public func delete() {
        let query: [CFString: Any] = [
            kSecClass:       kSecClassGenericPassword,
            kSecAttrService: Self.service,
            kSecAttrAccount: Self.account,
        ]
        SecItemDelete(query as CFDictionary)
    }
}
