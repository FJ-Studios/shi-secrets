import Crypto
import Foundation
import ShiSecretsKit

// Bootstrap — resolves the broker's Vaultwarden credentials and Ed25519
// signing key before the DI container is unsealed (BR-I-01, BR-I-02).
//
// W1 change (shi-secrets W1 — 2026-05-21):
//   The previous implementation read `$CREDENTIALS_DIRECTORY/bw-session`
//   from a systemd-creds injected file and passed it as the BW_SESSION
//   environment variable to a child `bw serve` process.
//
//   This implementation REPLACES that pattern:
//     - BW_SESSION env var: REMOVED. No getenv, no setenv, no env propagation.
//     - bw CLI subprocess: REMOVED. No Process() spawns.
//     - New path: KeychainVaultCredentials.load() → VaultwardenClient.connect()
//
//   On first run (no Keychain entry), Bootstrap surfaces a clear setup error
//   pointing to `shi secrets setup` (W2, task #113). The broker MUST refuse
//   to start with a specific error — no fallback, no env var check.
//
//   The signing key path is UNCHANGED for Linux (systemd-creds).
//   macOS Keychain migration for the signing key is W4.
//
// BR-SM-01, BR-SM-06, BR-SM-08

public enum BootstrapError: Swift.Error, Sendable, Equatable {
    /// Keychain entry not found — `shi secrets setup` (W2, task #113) not yet run.
    case keychainCredentialsMissing

    /// Keychain entry found but the JSON blob is corrupt.
    case keychainCredentialsMalformed

    /// macOS Security framework returned an unexpected OSStatus.
    case keychainOSError(status: Int32)

    /// VaultwardenClient.connect() failed (network, TLS, or auth error).
    case vaultwardenConnectFailed(message: String)

    /// Signing key credential file missing.
    case signingKeyMissing

    /// v1 refuses the TPM2 hardware-sealed path.
    case tpm2NotImplementedInV1

    /// Unsupported platform.
    case platformNotSupported(platform: String)

    /// Catch-all raised by BrokerDaemon.start on any bootstrap failure.
    /// Review finding U13 — keeps the error surface typed.
    case unsealFailed

    // Kept for call sites that still reference the old credential-path
    // error cases so they can be updated progressively in W2.
    @available(*, deprecated, message: "BW_SESSION path removed in W1; use keychainCredentialsMissing")
    static var credentialsDirectoryMissing: BootstrapError { .keychainCredentialsMissing }
    @available(*, deprecated, message: "BW_SESSION path removed in W1; use keychainCredentialsMissing")
    static func bwSessionFileMissing(path: String) -> BootstrapError { .keychainCredentialsMissing }
    @available(*, deprecated, message: "BW_SESSION path removed in W1; use keychainCredentialsMissing")
    static var bwSessionEmpty: BootstrapError { .keychainCredentialsMissing }
}

/// Abstraction of the unseal step used by BrokerDaemon.start / BrokerMain.main.
/// The default production type is `Bootstrap`; tests inject a throwing or
/// pre-satisfied implementation without touching the Keychain.
public protocol BootstrapProvider: Sendable {
    /// Throws if Keychain credentials are missing or Vaultwarden is unreachable.
    /// Returns the authenticated VaultwardenClient + signing-key pair on success.
    func unseal() async throws -> (vaultClient: VaultwardenClient, signingKey: BrokerSigningKey)
}

// Bootstrap captures a FileManager reference which Foundation does not
// vend as Sendable on Darwin. The type is otherwise immutable (let-only
// properties) and filesystem operations are read-only.
extension Bootstrap: BootstrapProvider, @unchecked Sendable {}

public enum BootstrapPlatform: String, Sendable, Equatable {
    case linux
    case darwin
}

public struct Bootstrap {

    public static let brokerSigningKeyCredName = "broker-signing-key"
    public static let keychainService = KeychainVaultCredentials.service

    /// Env key that overrides the Vaultwarden server URL (config-chain step 2).
    public static let vaultURLEnvKey = "SHIKKI_VAULT_URL"

    private let env: [String: String]
    private let fs: FileManager
    /// Optional override for config.yml `vault.server` (for testability).
    private let configYmlVaultServer: String?

    public init(
        env: [String: String] = ProcessInfo.processInfo.environment,
        fileManager: FileManager = .default,
        configYmlVaultServer: String? = nil
    ) {
        self.env = env
        self.fs = fileManager
        self.configYmlVaultServer = configYmlVaultServer
    }

    /// Load Vaultwarden credentials from the macOS Keychain, connect to
    /// the Vaultwarden API, and read the Ed25519 signing key.
    ///
    /// On missing Keychain entry, throws `.keychainCredentialsMissing` with
    /// a message pointing to `shi secrets setup` (W2, task #113).
    public func unseal() async throws -> (vaultClient: VaultwardenClient, signingKey: BrokerSigningKey) {
        // 1. Load credentials from Keychain (replaces getenv("BW_SESSION")).
        let credentials: VaultwardenCredentials
        do {
            credentials = try KeychainVaultCredentials().load()
        } catch KeychainVaultCredentials.KeychainError.itemNotFound {
            // Clear setup error — operator has not run `shi secrets setup` yet.
            // W2 task #113 ships that command.
            throw BootstrapError.keychainCredentialsMissing
        } catch KeychainVaultCredentials.KeychainError.dataMalformed {
            throw BootstrapError.keychainCredentialsMalformed
        } catch KeychainVaultCredentials.KeychainError.osError(let status) {
            throw BootstrapError.keychainOSError(status: status)
        }

        // 2. Connect to Vaultwarden (client_credentials token exchange).
        let vaultClient: VaultwardenClient
        do {
            vaultClient = try VaultwardenClient(
                credentials: credentials,
                configYmlVaultServer: configYmlVaultServer
            )
            try await vaultClient.connect()
        } catch {
            throw BootstrapError.vaultwardenConnectFailed(message: "\(error)")
        }

        // 3. Load signing key.
        let signingKey = try loadSigningKey()

        return (vaultClient, signingKey)
    }

    // MARK: - Signing key loading

    private func loadSigningKey() throws -> BrokerSigningKey {
        // On Linux the key lives in $CREDENTIALS_DIRECTORY/broker-signing-key.
        // On macOS dev, fall back to a fresh ephemeral key for local dev/CI.
        // macOS production migration to Keychain is W4.
        if let dir = env["CREDENTIALS_DIRECTORY"], !dir.isEmpty {
            let keyPath = dir + "/" + Self.brokerSigningKeyCredName
            if fs.fileExists(atPath: keyPath),
               let keyData = try? Data(contentsOf: URL(fileURLWithPath: keyPath)),
               !keyData.isEmpty {
                let trimmed = keyData.prefix(32)
                let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: trimmed)
                return BrokerSigningKey(privateKey: privateKey)
            }
        }
        #if os(Linux)
        throw BootstrapError.signingKeyMissing
        #else
        // HIGH-7: ephemeral key fallback is dev/CI ONLY. Production macOS must
        // supply the key via CREDENTIALS_DIRECTORY (same as Linux). When not in
        // DEBUG mode, treat a missing signing key as a hard error.
        #if DEBUG
        let devKey = Curve25519.Signing.PrivateKey()
        return BrokerSigningKey(privateKey: devKey)
        #else
        throw BootstrapError.signingKeyMissing
        #endif
        #endif
    }

    /// v1 rejects the TPM2 hardware-sealed path.
    public func refuseTpm2Path() throws {
        throw BootstrapError.tpm2NotImplementedInV1
    }

    /// Platform check — only Linux + Darwin are supported.
    public func requireSupportedPlatform(_ platform: BootstrapPlatform) throws {
        switch platform {
        case .linux, .darwin:
            return
        }
    }

    /// Documentation-only helper referenced by T48's v1.2-upgrade-path test.
    public static var v12UpgradePathDocumentation: String {
        "Wave 1: macOS Keychain (Security.framework "
        + "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly "
        + "+ kSecAccessControlBiometryCurrentSet) + VaultwardenClient HTTP actor. "
        + "v1.2 upgrade path: Secure Enclave sealing via SecKey "
        + "kSecAttrTokenIDSecureEnclave; Linux TPM2 unsealing is NOT "
        + "invested (see spec Phase 3 §I-05)."
    }
}
