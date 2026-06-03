import Foundation

// VaultCredentialsSeeder — testable core of `shi secrets setup vault-credentials`.
//
// Extracts the validation + Keychain-write + verify logic so it can be unit-tested
// without a live TTY or live Vaultwarden instance. The ArgumentParser command
// (`SecretsSetupVaultCredentialsCommand`) delegates entirely to this type.
//
// BR-SM-01, BR-NO-CRED-ENV — clientSecret NEVER printed; Keychain-only storage.
// Phase P0-close-2026-05-26

/// Seeder outcome — success with masked metadata or typed failure.
public enum SeedResult: Sendable, Equatable {
    /// Credentials written (and optionally verified) successfully.
    case seeded(clientIDPrefix: String)
    /// Write skipped because the entry exists and `force` is false.
    case alreadyExists
    /// clientID format is invalid.
    case invalidClientID(String)
    /// serverURL is not a well-formed https/http URL.
    case invalidServerURL(String)
    /// Keychain OSStatus error.
    case keychainError(Int32)
    /// Verification network error.
    case verifyFailed(String)
    /// Generic error.
    case failure(String)
}

/// Protocol allowing tests to swap in a recording/mock Keychain.
/// Uses async to allow actor conformances in tests.
public protocol VaultCredentialStore: Sendable {
    func load() async throws -> VaultwardenCredentials
    func store(_ credentials: VaultwardenCredentials, overwrite: Bool) async throws
    func delete() async
}

/// Default implementation — delegates to KeychainVaultCredentials.
/// Synchronous Keychain calls are wrapped in async noop continuations.
public struct LiveVaultCredentialStore: VaultCredentialStore, Sendable {
    public init() {}
    private let keychain = KeychainVaultCredentials()

    public func load() async throws -> VaultwardenCredentials {
        try keychain.load()
    }
    public func store(_ credentials: VaultwardenCredentials, overwrite: Bool) async throws {
        try keychain.store(credentials, overwrite: overwrite)
    }
    public func delete() async {
        keychain.delete()
    }
}

/// Verifier protocol so tests can skip the network call.
public protocol VaultConnectionVerifier: Sendable {
    func verify(credentials: VaultwardenCredentials) async throws
}

/// Default — uses VaultwardenClient to attempt an OAuth token grant.
public struct LiveVaultConnectionVerifier: VaultConnectionVerifier, Sendable {
    public init() {}
    public func verify(credentials: VaultwardenCredentials) async throws {
        let client = try VaultwardenClient(credentials: credentials)
        try await client.connect()
    }
}

/// Core seeder logic — no TTY, no ArgumentParser dependency.
public struct VaultCredentialsSeeder: Sendable {

    private let store: any VaultCredentialStore
    private let verifier: (any VaultConnectionVerifier)?

    public init(
        store: any VaultCredentialStore = LiveVaultCredentialStore(),
        verifier: (any VaultConnectionVerifier)? = LiveVaultConnectionVerifier()
    ) {
        self.store = store
        self.verifier = verifier
    }

    /// Validate + write + (optionally) verify credentials.
    ///
    /// - Parameters:
    ///   - clientID: Must start with "user."
    ///   - clientSecret: Raw secret — NEVER log this value.
    ///   - serverURL: Must be a valid https/http URL string.
    ///   - force: If false and an existing entry is found, returns `.alreadyExists`.
    ///   - verify: If true and a verifier is configured, attempt a token grant.
    ///
    /// - Returns: `SeedResult` — callers map this to exit codes and messages.
    public func seed(
        clientID: String,
        clientSecret: String,
        serverURL: String,
        force: Bool,
        verify: Bool
    ) async -> SeedResult {

        // Validate clientID format
        guard clientID.hasPrefix("user."), clientID.count > 5 else {
            return .invalidClientID(clientID)
        }

        // Validate serverURL
        guard let urlParsed = URL(string: serverURL),
              (urlParsed.scheme == "https" || urlParsed.scheme == "http"),
              urlParsed.host != nil else {
            return .invalidServerURL(serverURL)
        }

        // Check existing entry
        let existingEntry = try? await store.load()
        if existingEntry != nil && !force {
            return .alreadyExists
        }

        // Build credentials
        let credentials = VaultwardenCredentials(
            clientID: clientID,
            clientSecret: clientSecret,
            serverURL: urlParsed
        )

        // Write to Keychain
        do {
            try await store.store(credentials, overwrite: force || existingEntry == nil)
        } catch let e as KeychainVaultCredentials.KeychainError {
            switch e {
            case .itemAlreadyExists:
                return .alreadyExists
            case .osError(let status):
                return .keychainError(status)
            default:
                return .failure("Keychain error: \(e)")
            }
        } catch {
            return .failure("Keychain write failed: \(error)")
        }

        // Verify if requested
        if verify, let v = verifier {
            do {
                try await v.verify(credentials: credentials)
            } catch {
                // Revert the write on verify failure
                await store.delete()
                return .verifyFailed(String(describing: error))
            }
        }

        // Success — return only the clientID prefix (never the secret)
        let prefix = String(clientID.prefix(12))
        return .seeded(clientIDPrefix: prefix)
    }
}
