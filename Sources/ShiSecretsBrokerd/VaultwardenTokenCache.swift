// VaultwardenTokenCache — Keychain-backed OAuth token cache + JSON backoff store.
//
// W2 of spec e8c4a921-7d3b-4f5e-9a2c-1d6b8f4e3a91
// Panel #1 verdict (D8F2F0FCD05E484FBF56115911DE04C2): split storage design:
//   - token + expires_at → Keychain via SecureStore (AES-256, TM-excluded)
//   - consecutive_429_count + next_attempt_at + last_fetch → plain JSON file
//     (non-sensitive operational counters)
//
// Security invariants:
//   - The access token string NEVER touches the filesystem.
//   - BackoffEntry MUST NOT ever gain a `token`-like field (T-W2-K05 guards).
//   - JSON file is written with explicit fchmod(0o600) after atomic rename.
//
// Cross-platform injection: `SecureStore` protocol received at init — lets tests
// inject MockSecureStore instead of hitting the real Keychain (panel #2).
//
// See: super-challenge-w2-token-cache-disk-safety-2026-06-24.md §7
//      super-challenge-w2-cross-platform-secure-cache-2026-06-24.md §6

import Foundation
import ShiSecretsKit
#if canImport(os)
import os
#endif

// MARK: - VaultwardenTokenCache

/// Actor-isolated two-part cache:
/// - **Token half**: `read/writeToken()` → `SecureStore` (Keychain on Mac)
/// - **Backoff half**: `read/writeBackoff()` → plain JSON file, mode 0o600
actor VaultwardenTokenCache {

    // MARK: - Keychain coordinates

    /// Keychain service name. Canonical per operator decision 2026-06-24T1415Z:
    ///   `io.shikki.*` product domain (shikki.io), NOT `eu.fj-studios.shikki.*`.
    let keychainService = "io.shikki.vault.token"
    let keychainAccount = "client-credentials-access-token"

    // MARK: - Token entry (Keychain half)

    struct TokenEntry {
        let token: String
        let expiresAt: Date
        // NOTE: NOT Codable on purpose — prevents accidental JSON serialization
        // to disk (T-W2-K05). JSON encoding happens ONLY inside writeToken().
    }

    // MARK: - Backoff entry (file half)

    struct BackoffEntry: Codable {
        let consecutive429Count: Int
        let nextAttemptAt: Date
        let lastFetch: Date
        // INVARIANT: NEVER add a `token`, `accessToken`, `access_token`,
        // or similar field here. T-W2-K05 source-scan enforces this.
    }

    // MARK: - Dependencies

    private let store: any SecureStore
    private let backoffFilePath: String
    private let logger: ShikkiSecretsLogger

    // MARK: - Init

    /// - Parameter store: `SecureStore` for the token half. Inject
    ///   `MockSecureStore` in tests; use `KeychainSecureStore()` in production.
    /// - Parameter backoffFilePath: Full path for the JSON backoff file.
    ///   Defaults to `~/.shikki/credentials/.brokerd-backoff.json`.
    ///   Pass a temp path in tests to avoid touching the real credentials dir.
    init(
        store: any SecureStore,
        backoffFilePath: String? = nil,
        logger: ShikkiSecretsLogger = ShikkiSecretsLogger()
    ) {
        self.store = store
        self.backoffFilePath = backoffFilePath ?? VaultwardenTokenCache.defaultBackoffFilePath()
        self.logger = logger
    }

    static func defaultBackoffFilePath() -> String {
        let credDir = ProcessInfo.processInfo.environment["CREDENTIALS_DIRECTORY"]
            ?? "\(NSHomeDirectory())/.shikki/credentials"
        return "\(credDir)/.brokerd-backoff.json"
    }

    // MARK: - Token I/O (Keychain)

    /// Read the cached token. Returns `nil` if absent or if stored bytes are corrupt
    /// (corruption logs a warning and falls through to `nil` — triggers re-fetch).
    func readToken() async throws -> TokenEntry? {
        guard let data = try await store.read(service: keychainService,
                                              account: keychainAccount) else {
            logger.debug("[token-cache] cache miss — no Keychain entry")
            return nil
        }
        // Decode {"token":"...","expires_at":"ISO8601"}
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: String],
              let tokenStr = json["token"],
              let expiresAtStr = json["expires_at"],
              let expiresAt = ISO8601DateFormatter().date(from: expiresAtStr)
        else {
            logger.warning("[token-cache] Keychain entry malformed — deleting and re-fetching")
            try? await store.delete(service: keychainService, account: keychainAccount)
            return nil
        }
        return TokenEntry(token: tokenStr, expiresAt: expiresAt)
    }

    /// Write token + expiresAt to Keychain. The token string is NEVER written
    /// to any file on disk; only the Keychain blob is touched.
    func writeToken(_ token: String, expiresAt: Date) async throws {
        let payload: [String: String] = [
            "token":      token,
            "expires_at": ISO8601DateFormatter().string(from: expiresAt),
        ]
        let data = try JSONSerialization.data(withJSONObject: payload)
        try await store.write(data, service: keychainService, account: keychainAccount)
        logger.debug("[token-cache] token written to Keychain, expires \(ISO8601DateFormatter().string(from: expiresAt))")
    }

    /// Delete the cached token from Keychain.
    func deleteToken() async throws {
        try await store.delete(service: keychainService, account: keychainAccount)
        logger.debug("[token-cache] Keychain token entry deleted")
    }

    // MARK: - Backoff I/O (file)

    /// Read the backoff counters from the JSON file. Returns `nil` if absent or
    /// corrupt (corruption deletes the file, returns `nil` → counters restart at 0).
    func readBackoff() async throws -> BackoffEntry? {
        guard FileManager.default.fileExists(atPath: backoffFilePath) else {
            return nil
        }
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: backoffFilePath)) else {
            return nil
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        if let entry = try? decoder.decode(BackoffEntry.self, from: data) {
            return entry
        }
        // Corrupt file → delete and reset.
        logger.warning("[token-cache] backoff file corrupt — deleting, counters reset to 0")
        try? FileManager.default.removeItem(atPath: backoffFilePath)
        return nil
    }

    /// Write backoff counters atomically with mode 0o600.
    ///
    /// Uses write-to-temp + fchmod(0o600) + rename pattern so:
    /// 1. Mode 600 is set BEFORE the rename (Dgr-T1 from panel #1).
    /// 2. The rename is atomic — no partial file visible on crash.
    /// 3. Orphaned temp files have mode 600, not umask-default 644.
    func writeBackoff(_ entry: BackoffEntry) async throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = .prettyPrinted
        let data = try encoder.encode(entry)

        // Ensure parent directory exists.
        let dir = (backoffFilePath as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(
            atPath: dir, withIntermediateDirectories: true, attributes: nil
        )

        // Write to a sibling temp file first.
        let tmpPath = backoffFilePath + ".tmp.\(Int.random(in: 100_000..<999_999))"
        defer { try? FileManager.default.removeItem(atPath: tmpPath) }

        // Use POSIX open with O_CREAT | O_WRONLY | O_EXCL and explicit mode 0o600.
        // This guarantees the temp file starts with mode 600 — not umask-inherited.
        guard let cPath = tmpPath.cString(using: .utf8) else {
            throw CocoaError(.fileWriteInapplicableStringEncoding)
        }
        let fd = open(cPath, O_CREAT | O_WRONLY | O_EXCL, S_IRUSR | S_IWUSR)
        guard fd >= 0 else {
            throw CocoaError(.fileWriteNoPermission)
        }
        // Write bytes.
        let written = data.withUnsafeBytes { ptr in
            Foundation.write(fd, ptr.baseAddress!, data.count)
        }
        close(fd)
        guard written == data.count else {
            throw CocoaError(.fileWriteUnknown)
        }

        // Atomic rename: temp → final.
        guard rename(cPath, (backoffFilePath as NSString).fileSystemRepresentation) == 0 else {
            throw CocoaError(.fileWriteUnknown)
        }

        // Belt-and-suspenders: explicitly chmod the final file.
        // Darwin's rename() preserves the mode we set on the temp file,
        // but an explicit fchmod on the path removes ambiguity.
        let finalFd = open((backoffFilePath as NSString).fileSystemRepresentation,
                           O_RDONLY)
        if finalFd >= 0 {
            fchmod(finalFd, S_IRUSR | S_IWUSR)
            close(finalFd)
        }
    }

    // MARK: - High-level orchestration

    /// Record a successful token exchange:
    /// 1. Write new token to Keychain.
    /// 2. Reset backoff counters to zero.
    func recordSuccess(token: String, ttl: TimeInterval) async throws {
        let expiresAt = Date().addingTimeInterval(ttl)
        try await writeToken(token, expiresAt: expiresAt)
        let reset = BackoffEntry(consecutive429Count: 0,
                                 nextAttemptAt: Date(),
                                 lastFetch: Date())
        try await writeBackoff(reset)
        logger.info("[token-cache] token cached successfully, TTL=\(Int(ttl))s")
    }

    /// Record a 429 response.
    /// - Returns: Seconds to wait before the next attempt (capped at 30min).
    func record429() async throws -> TimeInterval {
        let current = try await readBackoff() ?? BackoffEntry(
            consecutive429Count: 0,
            nextAttemptAt: Date(),
            lastFetch: Date()
        )
        let newCount = current.consecutive429Count + 1
        // Exponential backoff: 60s * 2^(count-1), capped at 1800s (30min).
        let delay = min(60.0 * pow(2.0, Double(newCount - 1)), 1800.0)
        let nextAttempt = Date().addingTimeInterval(delay)
        let updated = BackoffEntry(
            consecutive429Count: newCount,
            nextAttemptAt: nextAttempt,
            lastFetch: current.lastFetch
        )
        try await writeBackoff(updated)
        logger.warning("[token-cache] 429 received (count=\(newCount)), next attempt in \(Int(delay))s")
        return delay
    }

    /// Reset the backoff counter (called after a successful 200 OK).
    func resetBackoff() async throws {
        let reset = BackoffEntry(consecutive429Count: 0,
                                 nextAttemptAt: Date(),
                                 lastFetch: Date())
        try await writeBackoff(reset)
    }
}
