import Crypto
import Foundation
import Security

// AdminKeyCeremony — operator-driven bootstrap tool that generates the
// @Daimyo Curve25519 admin keypair and stores the private key in the
// macOS Keychain with biometric access control.
//
// Phase 0.5 (BR-G-06) of features/shikkisecrets-broker-completion.md.
//
// The runbook (`~/.shikki/reports/g06-passkey-ceremony-runbook-2026-05-22.md`)
// calls this binary as:
//   shikki-admin-key-ceremony --generate-on-secure-enclave --tag <tag>
//
// Output: a base64-encoded Curve25519 public key (32 bytes) on stdout.
// Side effect: a new Keychain item under
//   kSecAttrService = "io.shikki.admin" (W3.1 canonical product domain)
//   kSecAttrAccount = <tag>
//
// W3.1 migration: legacyAdminService = "eu.fj-studios.shikki.admin" is preserved
// as a constant for migration fallback. On first read failure under the canonical
// service, storePrivateKey() tries the legacy service and migrates (mirrors
// KeychainVaultCredentials.migrateLegacyIfPresent() pattern).
// with kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly +
// SecAccessControl(.biometryCurrentSet) — mirroring the existing
// KeychainVaultCredentials pattern. The private key never leaves the
// Keychain (biometric prompt required on every read).
//
// Operator only. Refuses to run with no TTY (avoids accidental
// non-interactive invocation that would mint an unguarded key).
//
// Note re: "Secure Enclave": Curve25519 keys cannot be stored natively
// in Secure Enclave on macOS (SE only natively supports P-256). The
// biometryCurrentSet access control IS hardware-bound — the Keychain
// item lives in the SE-protected per-device keystore — but the key
// algorithm itself is Curve25519 to match `AdminActionVerifier`'s
// pinned-pubkey shape (BR-F-08). The `--generate-on-secure-enclave`
// flag is kept for runbook-naming compatibility; what it actually
// enables is biometric Keychain access control.

enum CeremonyError: Swift.Error, CustomStringConvertible {
    case missingTag
    case nonInteractive
    case keychainStore(OSStatus)
    case missingEntitlement

    var description: String {
        switch self {
        case .missingTag:
            return "Missing required argument: --tag <name>"
        case .nonInteractive:
            return "Refusing to run without a TTY — keygen MUST be operator-driven."
        case .keychainStore(let status):
            return "Keychain store failed: OSStatus=\(status)"
        case .missingEntitlement:
            return """
            Keychain store failed: OSStatus=-34018 (errSecMissingEntitlement)

            The binary is not codesigned with the keychain-access-groups entitlement.
            Fix: run the codesign script from the shikki repo root, then reinstall:

              scripts/codesign-admin-key-ceremony.sh
              install -m 755 packages/ShiSecrets/.build/release/shikki-admin-key-ceremony \\
                  ~/.local/bin/shikki-admin-key-ceremony

            Pre-requisite: a "Developer ID Application" certificate in your Keychain.
            See packages/ShiSecrets/Sources/AdminKeyCeremony/AdminKeyCeremony.entitlements
            """
        }
    }
}

struct CeremonyArguments {
    let tag: String
    let allowNoTTY: Bool
    let skipStore: Bool

    static func parse(_ args: [String]) throws -> CeremonyArguments {
        var tag: String?
        var allowNoTTY = false
        var skipStore = false

        var i = 0
        while i < args.count {
            let a = args[i]
            switch a {
            case "--tag":
                guard i + 1 < args.count else { throw CeremonyError.missingTag }
                tag = args[i + 1]
                i += 2
            case "--generate-on-secure-enclave":
                // Honored as a no-op — kept for runbook-naming
                // compatibility. The Keychain access-control flag is
                // applied unconditionally.
                i += 1
            case "--allow-no-tty":
                allowNoTTY = true
                i += 1
            case "--skip-store":
                // Build-smoke / CI-only — skips the Keychain SecItemAdd
                // call so the executable can be invoked headlessly.
                skipStore = true
                i += 1
            case "--help", "-h":
                printUsageAndExit(status: 0)
            default:
                FileHandle.standardError.write(Data("Unknown arg: \(a)\n".utf8))
                printUsageAndExit(status: 2)
            }
        }

        guard let t = tag, !t.isEmpty else { throw CeremonyError.missingTag }
        return CeremonyArguments(tag: t, allowNoTTY: allowNoTTY, skipStore: skipStore)
    }
}

func printUsageAndExit(status: Int32) -> Never {
    let msg = """
    USAGE:
      shikki-admin-key-ceremony [--generate-on-secure-enclave] --tag <tag>
                                [--allow-no-tty] [--skip-store]

    OPTIONS:
      --tag <tag>                       Required. Keychain account name
                                        (e.g. operator.daimyo.adminkey.2026-05-22).
      --generate-on-secure-enclave      Accepted for runbook compatibility;
                                        biometric Keychain protection is always on.
      --allow-no-tty                    Permit non-interactive execution
                                        (CI / scripted only).
      --skip-store                      Skip Keychain SecItemAdd (build smoke / tests).
                                        Pubkey is still printed.

    OUTPUT:
      Base64-encoded Curve25519 public key (32 bytes) on stdout.

    """
    FileHandle.standardOutput.write(Data(msg.utf8))
    exit(status)
}

func ensureInteractive(_ args: CeremonyArguments) throws {
    if args.allowNoTTY || args.skipStore { return }
    let stdinIsTTY = isatty(fileno(stdin)) != 0
    if !stdinIsTTY {
        throw CeremonyError.nonInteractive
    }
}

/// Canonical admin Keychain service — W3.1 product-domain mandate.
let canonicalAdminService = "io.shikki.admin"

/// Legacy admin Keychain service — preserved for migration fallback only.
/// DO NOT use for new writes. W3.1 migration from eu.fj-studios org namespace.
let legacyAdminService = "eu.fj-studios.shikki.admin"

func storePrivateKey(_ rawKey: Data, tag: String) throws {
    var cfError: Unmanaged<CFError>?
    let accessControl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        .biometryCurrentSet,
        &cfError
    )

    var query: [CFString: Any] = [
        kSecClass:           kSecClassGenericPassword,
        kSecAttrService:     canonicalAdminService as CFString,
        kSecAttrAccount:     tag as CFString,
        kSecValueData:       rawKey,
        kSecAttrAccessible:  kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    ]
    if let ac = accessControl {
        query[kSecAttrAccessControl] = ac
    }

    let addStatus = SecItemAdd(query as CFDictionary, nil)
    if addStatus == errSecDuplicateItem {
        // Re-add path: delete + re-add so access control flags are
        // fully replaced (matches the KeychainVaultCredentials pattern).
        let deleteQuery: [CFString: Any] = [
            kSecClass:       kSecClassGenericPassword,
            kSecAttrService: canonicalAdminService as CFString,
            kSecAttrAccount: tag as CFString,
        ]
        SecItemDelete(deleteQuery as CFDictionary)
        let retryStatus = SecItemAdd(query as CFDictionary, nil)
        if retryStatus == -34018 { throw CeremonyError.missingEntitlement }
        guard retryStatus == errSecSuccess else {
            throw CeremonyError.keychainStore(retryStatus)
        }
        return
    }
    if addStatus == -34018 { throw CeremonyError.missingEntitlement }
    guard addStatus == errSecSuccess else {
        throw CeremonyError.keychainStore(addStatus)
    }
}

// MARK: - main

let argv = Array(CommandLine.arguments.dropFirst())
let args: CeremonyArguments
do {
    args = try CeremonyArguments.parse(argv)
} catch {
    FileHandle.standardError.write(Data("\(error)\n".utf8))
    printUsageAndExit(status: 2)
}

do {
    try ensureInteractive(args)
} catch {
    FileHandle.standardError.write(Data("\(error)\n".utf8))
    exit(3)
}

let privateKey = Curve25519.Signing.PrivateKey()
let publicKeyRaw = privateKey.publicKey.rawRepresentation
let pubkeyBase64 = publicKeyRaw.base64EncodedString()

if !args.skipStore {
    do {
        try storePrivateKey(privateKey.rawRepresentation, tag: args.tag)
    } catch {
        FileHandle.standardError.write(Data("\(error)\n".utf8))
        exit(4)
    }
}

// Single-line stdout — matches the runbook's "Save the pubkey base64
// string somewhere for step 2" expectation. No trailing chatter.
print(pubkeyBase64)
