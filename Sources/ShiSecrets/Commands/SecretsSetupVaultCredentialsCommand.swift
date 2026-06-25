// SecretsSetupVaultCredentialsCommand — `shi secrets setup vault-credentials`
//
// Seeds Vaultwarden OAuth credentials (client_id, client_secret, server_url)
// into the macOS Keychain. First-time setup, after Keychain wipe, or after
// Bitwarden API key rotation.
//
// OVERVIEW:
//   Seed Vaultwarden OAuth credentials (client_id, client_secret, server_url)
//   into the macOS Keychain. First-time setup, after Keychain wipe, or after
//   Bitwarden API key rotation.
//
// Get client_id + client_secret from your Bitwarden account at
//   Settings → Security → Keys → API Key.
//
// Delegates all validation + Keychain write + verify logic to
// VaultCredentialsSeeder so behaviour is fully unit-testable without a TTY
// or live Vaultwarden instance.
//
// Flags:
//   --client-id    <user.UUID>     Required. Bitwarden client_id (must start with "user.").
//   --server-url   <https://...>   Required. Vaultwarden instance URL.
//   --client-secret <secret>       Optional. Reads from stdin (no-echo) if omitted.
//                                  Pass "-" to read a single line from stdin explicitly.
//   --force                        Overwrite an existing Keychain entry (default: error).
//   --no-verify                    Skip the OAuth round-trip verification.
//
// Output (on success): ONE line — "Vault credentials seeded for <host> — clientID prefix: <prefix>"
// Client secret is NEVER echoed in stdout, stderr, or logs (BR-SM-01, BR-NO-CRED-ENV).
//
// W3.1 — spec e8c4a921-7d3b-4f5e-9a2c-1d6b8f4e3a91

import Foundation
import ShiSecretsKit

/// `shi secrets setup vault-credentials` — seed Vaultwarden credentials into the Keychain.
public struct SecretsSetupVaultCredentialsCommand {

    // MARK: - Parsed parameters

    public let clientID: String
    public let serverURL: String
    public let clientSecretArg: String?   // nil = prompt; "-" = read one stdin line
    public let force: Bool
    public let noVerify: Bool

    // MARK: - Dependencies (injectable for tests)

    private let store: any VaultCredentialStore
    private let verifier: (any VaultConnectionVerifier)?
    private let secretReader: () -> String?   // injectable for tests (avoids real getpass)

    // MARK: - Init

    /// Production init — uses real Keychain and real verifier.
    public init(
        clientID: String,
        serverURL: String,
        clientSecretArg: String?,
        force: Bool,
        noVerify: Bool
    ) {
        self.clientID = clientID
        self.serverURL = serverURL
        self.clientSecretArg = clientSecretArg
        self.force = force
        self.noVerify = noVerify
        self.store = LiveVaultCredentialStore()
        self.verifier = noVerify ? nil : LiveVaultConnectionVerifier()
        self.secretReader = { Self.readPasswordFromTTY() }
    }

    /// Testable init — inject mock store, verifier, and secret reader.
    public init(
        clientID: String,
        serverURL: String,
        clientSecretArg: String?,
        force: Bool,
        noVerify: Bool,
        store: any VaultCredentialStore,
        verifier: (any VaultConnectionVerifier)?,
        secretReader: @escaping () -> String? = { nil }
    ) {
        self.clientID = clientID
        self.serverURL = serverURL
        self.clientSecretArg = clientSecretArg
        self.force = force
        self.noVerify = noVerify
        self.store = store
        self.verifier = verifier
        self.secretReader = secretReader
    }

    // MARK: - run() -> Int32

    /// Execute the command. Returns an exit code.
    ///
    /// - Returns: 0 on success, non-zero on validation/keychain/verify failure.
    public func run() async -> Int32 {
        // 1. W3.1: Run legacy migration before any Keychain op.
        //    In case the operator seeded under eu.fj-studios.shikki.vault,
        //    auto-upgrade to io.shikki.vault before the store.load() check.
        let keychainDirect = KeychainVaultCredentials()
        try? keychainDirect.migrateLegacyIfPresent()

        // 2. Resolve client secret.
        let resolvedSecret: String
        if let arg = clientSecretArg {
            if arg == "-" {
                // Explicit stdin read (single line).
                guard let line = readLine(strippingNewline: true), !line.isEmpty else {
                    fputs("ERROR: No client_secret read from stdin.\n", stderr)
                    return 1
                }
                resolvedSecret = line
            } else {
                resolvedSecret = arg
            }
        } else {
            // No --client-secret arg — prompt with no-echo via getpass(3).
            guard let secret = secretReader(), !secret.isEmpty else {
                fputs("ERROR: No client_secret provided. Use --client-secret or pipe via --client-secret -.\n", stderr)
                return 1
            }
            resolvedSecret = secret
        }

        // 3. Delegate to VaultCredentialsSeeder (testable core).
        let seeder = VaultCredentialsSeeder(
            store: store,
            verifier: noVerify ? nil : verifier
        )
        let result = await seeder.seed(
            clientID: clientID,
            clientSecret: resolvedSecret,
            serverURL: serverURL,
            force: force,
            verify: !noVerify
        )

        // 4. Map result to output + exit code.
        return handleResult(result, serverURL: serverURL)
    }

    // MARK: - Result handling

    private func handleResult(_ result: SeedResult, serverURL: String) -> Int32 {
        switch result {
        case .seeded(let clientIDPrefix):
            // Derive host for display. Ignore URL parse failure — we validated already.
            let host = URL(string: serverURL)?.host ?? serverURL
            // Output ONE line. client_secret NEVER echoed.
            print("Vault credentials seeded for \(host) — clientID prefix: \(clientIDPrefix)")
            return 0

        case .alreadyExists:
            fputs(
                """
                ERROR: Vault credentials already exist in the Keychain.
                Run with --force to overwrite the existing entry.
                """,
                stderr
            )
            return 1

        case .invalidClientID(let id):
            fputs(
                """
                ERROR: Invalid client_id: "\(id)"
                The client_id must start with "user." (e.g. user.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).
                Get your client_id from Bitwarden: Settings → Security → Keys → API Key.
                """,
                stderr
            )
            return 1

        case .invalidServerURL(let url):
            fputs(
                """
                ERROR: Invalid server_url: "\(url)"
                Must be a valid https:// or http:// URL with a host (e.g. https://vw.example.com).
                """,
                stderr
            )
            return 1

        case .keychainError(let status):
            fputs("ERROR: Keychain write failed (OSStatus=\(status)).\n", stderr)
            if status == -34018 {
                fputs(
                    "Hint: The binary may not be codesigned with keychain-access-groups entitlements.\n",
                    stderr
                )
            }
            return 1

        case .verifyFailed(let reason):
            fputs(
                """
                ERROR: Vault connection verification failed: \(reason)
                The credentials were saved to Keychain but the OAuth round-trip failed.
                Check your server URL and Bitwarden API key, then run again with --force to retry.
                Use --no-verify to skip verification (e.g. when the vault is temporarily unreachable).
                """,
                stderr
            )
            return 1

        case .failure(let message):
            fputs("ERROR: \(message)\n", stderr)
            return 1
        }
    }

    // MARK: - TTY helpers

    /// Read a password from the TTY without echoing it, using getpass(3).
    /// Returns nil if the TTY is unavailable or getpass returns empty.
    private static func readPasswordFromTTY() -> String? {
        fputs("Enter Bitwarden client_secret (no echo): ", stderr)
        // getpass(3) reads from /dev/tty directly (not stdin), so it works
        // even when stdin is redirected. The prompt arg is written to /dev/tty.
        // We pass our own prompt above, so pass empty string to getpass.
        guard let ptr = getpass("") else { return nil }
        let secret = String(cString: ptr)
        return secret.isEmpty ? nil : secret
    }
}
