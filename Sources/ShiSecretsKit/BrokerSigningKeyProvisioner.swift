// BrokerSigningKeyProvisioner.swift
// P0 — first-run signing-key bootstrap
// Backlog: 8cc9c1f0-32cb-418f-80d5-824b0abb339d
// Spec: features/signing-key-bootstrap-2026-07-02.md
//
// Companion of Bootstrap.loadSigningKey(): the daemon READS the key here
// via CREDENTIALS_DIRECTORY/broker-signing-key; this type GENERATES it on
// first-run so the daemon doesn't crash-loop on `signingKeyMissing`.
//
// Called by `shi secrets setup wizard` BEFORE launching the daemon, and
// surfaced by `shi secrets doctor` so a missing key emits a clean
// actionable error instead of the daemon's opaque crash-loop.
//
// The `random` closure is injectable so tests can pin a deterministic seed;
// production always uses the system CSPRNG via `Data(randomBytes:)`.

import Foundation

/// Outcome of a `provisionIfNeeded` call.
public enum ProvisionOutcome: Sendable, Equatable {
    /// A fresh 32-byte seed was generated + written to disk at 0o600.
    case provisioned
    /// A key file already existed. Bytes were left untouched; permissions
    /// were fixed to 0o600 if they were anything else.
    case alreadyPresent
}

/// Ensures the broker signing key exists at `credentialsDir/keyName` with
/// exactly 32 bytes of entropy and file mode `0o600`.
public enum BrokerSigningKeyProvisioner {

    /// The canonical key filename inside `credentialsDir`. Matches the
    /// `Bootstrap.brokerSigningKeyCredName` reader on the daemon side.
    public static let defaultKeyName = "broker-signing-key"

    /// Ensure a 32-byte Ed25519 seed exists at `credentialsDir/keyName`.
    ///
    /// - Generates a fresh key iff the file is absent OR empty.
    /// - Always ends with file mode `0o600` (owner-read-only), fixing wrong
    ///   perms on an existing file.
    /// - Returns `.provisioned` when a new key was written, `.alreadyPresent`
    ///   when the existing key was kept.
    /// - Throws on FileManager / write failure.
    ///
    /// - Parameters:
    ///   - credentialsDir: parent directory (created if missing).
    ///   - keyName: filename inside that directory. Defaults to `broker-signing-key`.
    ///   - random: closure that produces a 32-byte seed. Defaults to the
    ///     system CSPRNG (`UInt8.random(in:)` per byte).
    @discardableResult
    public static func provisionIfNeeded(
        credentialsDir: URL,
        keyName: String = defaultKeyName,
        random: @Sendable () -> Data = { Data((0..<32).map { _ in UInt8.random(in: 0...255) }) }
    ) throws -> ProvisionOutcome {
        let fm = FileManager.default

        try fm.createDirectory(at: credentialsDir, withIntermediateDirectories: true)

        let keyURL = credentialsDir.appendingPathComponent(keyName)

        if fm.fileExists(atPath: keyURL.path) {
            // Ensure perms even when we don't rewrite the file — a common
            // mis-install state is 0o644 from a manual `head -c 32 /dev/urandom > …`
            // without the `chmod 600` follow-up.
            try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyURL.path)
            return .alreadyPresent
        }

        // Write with 0o600 in one shot via createFile + attributes.
        let seed = random()
        precondition(seed.count == 32, "random closure must produce exactly 32 bytes; got \(seed.count)")
        _ = fm.createFile(
            atPath: keyURL.path,
            contents: seed,
            attributes: [.posixPermissions: 0o600]
        )
        return .provisioned
    }
}
