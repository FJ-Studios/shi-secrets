// MachineAccountSeeder — W6.5c entry-point for the master-password-free
// brokerd onboarding flow (F-PSA-1, F-PSA-2, F-PSA-4).
//
// Replaces the deprecated W6.5b `--reauth` master-password prompt with
// system-name + machine_account `client_credentials` paste. Composes
// SystemNamePolicy (system-name validation) + VaultCredentialsSeeder
// (Keychain write) — strictly via BR-COMPOSE, no subprocess.
//
// Inputs:
//   - candidateSystemName  (operator paste, validated via SystemNamePolicy)
//   - clientID             (must start with "user." or "machine.")
//   - clientSecret         (machine_account secret, NEVER logged)
//   - serverURL            (Vaultwarden / Bitwarden)
//
// Regression guards (the spec's T-W6.5c-02):
//   - The wizard MUST NEVER accept the operator's master password. A
//     password-grant prompt looks NOTHING like a machine_account paste
//     (UUID vs email + master password). We refuse here if heuristics
//     detect a password-grant attempt (whitespace in clientSecret,
//     "@" in clientID without "machine." prefix, "password" keyword).

import Foundation

public struct MachineAccountSeeder: Sendable {

    private let store: any VaultCredentialStore
    private let systemNameWriter: SystemNameWriting

    public init(
        store: any VaultCredentialStore = LiveVaultCredentialStore(),
        systemNameWriter: SystemNameWriting = LiveSystemNameWriter()
    ) {
        self.store = store
        self.systemNameWriter = systemNameWriter
    }

    /// Validate inputs, refuse password-grant lookalikes, persist system name
    /// + credentials, return a typed outcome.
    public func seed(
        candidateSystemName: String,
        clientID: String,
        clientSecret: String,
        serverURL: String,
        force: Bool
    ) async -> Outcome {
        // 1. Validate system name.
        let systemName: String
        switch SystemNamePolicy.validate(candidateSystemName) {
        case .success(let n): systemName = n
        case .failure(let e): return .invalidSystemName(reason: e)
        }

        // 2. Refuse anything that looks like a password-grant attempt.
        if let smell = passwordGrantSmell(clientID: clientID, clientSecret: clientSecret) {
            return .refusedPasswordGrantLookalike(smell: smell)
        }

        // 3. Delegate the actual write to the existing VaultCredentialsSeeder.
        //    v0.4.3 HIGH-2 fix: pass `boundSystemName: systemName` so the
        //    credential blob carries the name it was provisioned for. Brokerd
        //    boot uses SystemNameBindingVerifier to refuse start on
        //    sidecar-vs-blob divergence (cache poisoning).
        let seeder = VaultCredentialsSeeder(store: store, verifier: nil)
        let seedResult = await seeder.seed(
            clientID: clientID,
            clientSecret: clientSecret,
            serverURL: serverURL,
            boundSystemName: systemName,
            force: force,
            verify: false
        )
        switch seedResult {
        case .seeded(let prefix):
            // 4. Persist the system name for brokerd boot-time loading.
            do {
                try systemNameWriter.write(systemName: systemName)
            } catch {
                return .systemNameWriteFailed(reason: "\(error)")
            }
            return .seeded(systemName: systemName, clientIDPrefix: prefix)
        case .alreadyExists:
            return .alreadyExists
        case .invalidClientID(let s):
            return .invalidClientID(s)
        case .invalidServerURL(let s):
            return .invalidServerURL(s)
        case .keychainError(let st):
            return .keychainError(status: st)
        case .verifyFailed(let m), .failure(let m):
            return .underlyingFailure(message: m)
        }
    }

    // MARK: - Outcome

    public enum Outcome: Sendable, Equatable {
        case seeded(systemName: String, clientIDPrefix: String)
        case alreadyExists
        case invalidSystemName(reason: SystemNamePolicy.ValidationError)
        case refusedPasswordGrantLookalike(smell: PasswordGrantSmell)
        case invalidClientID(String)
        case invalidServerURL(String)
        case keychainError(status: Int32)
        case systemNameWriteFailed(reason: String)
        case underlyingFailure(message: String)
    }

    // MARK: - Password-grant heuristics

    public enum PasswordGrantSmell: String, Sendable, Equatable {
        case clientSecretContainsWhitespace
        case clientIDLooksLikeEmail
        case clientSecretContainsPasswordKeyword

        public var operatorMessage: String {
            switch self {
            case .clientSecretContainsWhitespace:
                return "client_secret contains whitespace — Bitwarden API secrets are URL-safe tokens, this looks like a typed password"
            case .clientIDLooksLikeEmail:
                return "client_id looks like an email address — Bitwarden API client_id starts with 'user.' or 'machine.'"
            case .clientSecretContainsPasswordKeyword:
                return "client_secret contains the word 'password' — refusing as a likely paste error"
            }
        }
    }

    /// LOW-1 fix: made `public` so external test targets can verify the
    /// regression-guard heuristics without needing `@testable import`.
    public func passwordGrantSmell(clientID: String, clientSecret: String) -> PasswordGrantSmell? {
        // MED-2 fix: catch ALL Unicode whitespace categories (non-breaking
        // space, zero-width, BOM, tabs, newlines) — not just ASCII space + tab.
        if clientSecret.unicodeScalars.contains(where: { $0.properties.isWhitespace })
            || clientSecret.unicodeScalars.contains(where: { $0 == "\u{FEFF}" || $0 == "\u{200B}" || $0 == "\u{200C}" || $0 == "\u{200D}" })
        {
            return .clientSecretContainsWhitespace
        }
        if clientID.contains("@") && !clientID.hasPrefix("user.") && !clientID.hasPrefix("machine.") {
            return .clientIDLooksLikeEmail
        }
        if clientSecret.lowercased().contains("password") {
            return .clientSecretContainsPasswordKeyword
        }
        return nil
    }
}

// MARK: - System-name persistence

public protocol SystemNameWriting: Sendable {
    func write(systemName: String) throws
    func read() throws -> String?
}

public struct LiveSystemNameWriter: SystemNameWriting {

    public init() {}

    /// Resolves the location for the system-name sidecar.
    /// Default: `~/.shikki/etc/secrets/system-name`
    public static var defaultPath: String {
        return NSString(string: "~/.shikki/etc/secrets/system-name").expandingTildeInPath
    }

    public func write(systemName: String) throws {
        let path = Self.defaultPath
        let dir = (path as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(
            atPath: dir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        // v0.4.3 MED-6 fix (@security panel): avoid the symlink race between
        // createDirectory + write(toFile:atomically:) by using low-level
        // open(2) with O_NOFOLLOW | O_CREAT | O_EXCL | O_WRONLY. This refuses
        // to follow any pre-existing symlink at the target path AND fails
        // if the file already exists (forcing the caller to handle replace
        // explicitly). Mode 0o600 set at create time, not after.
        let payload = (systemName + "\n").data(using: .utf8) ?? Data()
        // Best-effort cleanup of any pre-existing entry (regular file OR
        // symlink). We use unlink(2) which works on both; if it fails the
        // open below will fail with EEXIST and we surface the error.
        path.withCString { _ = unlink($0) }
        let fd = path.withCString { cpath -> Int32 in
            Darwin.open(cpath, O_NOFOLLOW | O_CREAT | O_EXCL | O_WRONLY, 0o600)
        }
        guard fd >= 0 else {
            throw NSError(
                domain: NSPOSIXErrorDomain, code: Int(errno),
                userInfo: [NSLocalizedDescriptionKey: "open(O_NOFOLLOW|O_CREAT|O_EXCL) failed for \(path): errno=\(errno) (\(String(cString: strerror(errno))))"]
            )
        }
        defer { close(fd) }
        let written = payload.withUnsafeBytes { (buf: UnsafeRawBufferPointer) -> Int in
            return Darwin.write(fd, buf.baseAddress, buf.count)
        }
        guard written == payload.count else {
            throw NSError(
                domain: NSPOSIXErrorDomain, code: Int(errno),
                userInfo: [NSLocalizedDescriptionKey: "short write to \(path): wrote=\(written) expected=\(payload.count)"]
            )
        }
    }

    public func read() throws -> String? {
        let path = Self.defaultPath
        guard FileManager.default.fileExists(atPath: path) else { return nil }
        let raw = try String(contentsOfFile: path, encoding: .utf8)
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}

/// In-memory writer for tests — never touches disk.
public final class InMemorySystemNameWriter: SystemNameWriting, @unchecked Sendable {

    private var stored: String?
    private let lock = NSLock()

    public init(initial: String? = nil) {
        self.stored = initial
    }

    public func write(systemName: String) throws {
        lock.lock(); defer { lock.unlock() }
        stored = systemName
    }

    public func read() throws -> String? {
        lock.lock(); defer { lock.unlock() }
        return stored
    }
}
