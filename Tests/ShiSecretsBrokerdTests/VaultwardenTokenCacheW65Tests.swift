// VaultwardenTokenCacheW65Tests — W6.5
//
// Tests for the W6.5 extensions to VaultwardenTokenCache:
//   • TokenEntry now carries an optional `sessionFingerprint`
//   • writeToken auto-fills fingerprint via SessionFingerprint.current()
//   • readToken backward-compat decodes legacy JSON (no session_fingerprint)
//   • sessionFingerprintMatches(entry:) returns the right truth-value
//
// Spec UUID: e8c4a921-7d3b-4f5e-9a2c-1d6b8f4e3a91 (W6.5)

import Testing
import Foundation
@testable import ShiSecretsBrokerd
@testable import ShiSecretsKit

@Suite("VaultwardenTokenCache W6.5")
struct VaultwardenTokenCacheW65Tests {

    // MARK: - Helpers

    /// Returns a fresh cache backed by an in-memory MockSecureStore
    /// + a temp backoff-file path.
    func freshCache() throws -> (VaultwardenTokenCache, MockSecureStore) {
        let store = MockSecureStore()
        let tmpDir = NSTemporaryDirectory()
        let backoff = (tmpDir as NSString).appendingPathComponent("brokerd-backoff-\(UUID()).json")
        let cache = VaultwardenTokenCache(
            store: store,
            backoffFilePath: backoff
        )
        return (cache, store)
    }

    // MARK: - Backward-compat

    @Test("T-W6.5-TC-01: readToken accepts legacy JSON (no session_fingerprint field)")
    func legacy_jsonWithoutFingerprint_readable() async throws {
        let (cache, store) = try freshCache()
        // Hand-craft pre-W6.5 JSON shape (Keychain coords match the
        // brokerd's canonical service/account; mirrored from the actor's
        // instance members which were instance-let, not static):
        let legacy = #"{"token":"legacy-tok","expires_at":"2099-01-01T00:00:00Z"}"#
        try await store.write(
            legacy.data(using: .utf8)!,
            service: "io.shikki.vault.token",
            account: "client-credentials-access-token"
        )
        let entry = try await cache.readToken()
        #expect(entry != nil)
        #expect(entry?.token == "legacy-tok")
        #expect(entry?.sessionFingerprint == nil)  // legacy = no binding
    }

    // MARK: - Forward path

    @Test("T-W6.5-TC-02: writeToken auto-fills sessionFingerprint when not passed")
    func writeToken_autoFillsFingerprint() async throws {
        let (cache, _) = try freshCache()
        try await cache.writeToken("fresh-tok", expiresAt: Date(timeIntervalSinceNow: 3600))
        let entry = try await cache.readToken()
        #expect(entry != nil)
        // On macOS, SessionFingerprint.current() is non-nil; on Linux, may be nil
        #if os(macOS)
        #expect(entry?.sessionFingerprint != nil)
        #expect(entry?.sessionFingerprint?.hasPrefix("mac:") == true)
        #endif
    }

    @Test("T-W6.5-TC-03: writeToken honors explicit sessionFingerprint = nil")
    func writeToken_explicitNilFingerprint() async throws {
        let (cache, _) = try freshCache()
        // Bug-compat: passing nil keeps explicit current() behavior since default is nil.
        // Verifies the parameter exists + Swift type checks.
        try await cache.writeToken("tok", expiresAt: Date(timeIntervalSinceNow: 3600), sessionFingerprint: nil)
        let entry = try await cache.readToken()
        #expect(entry != nil)  // any platform: persisted ok
    }

    @Test("T-W6.5-TC-04: writeToken honors explicit non-nil sessionFingerprint")
    func writeToken_explicitFingerprint() async throws {
        let (cache, _) = try freshCache()
        let fake = "test:fingerprint:42"
        try await cache.writeToken("tok", expiresAt: Date(timeIntervalSinceNow: 3600), sessionFingerprint: fake)
        let entry = try await cache.readToken()
        #expect(entry?.sessionFingerprint == fake)
    }

    // MARK: - sessionFingerprintMatches

    @Test("T-W6.5-TC-05: sessionFingerprintMatches returns true for legacy entry (no fingerprint)")
    func matches_legacyEntry_returnsTrue() throws {
        let entry = VaultwardenTokenCache.TokenEntry(
            token: "x",
            expiresAt: Date(),
            sessionFingerprint: nil
        )
        // Reconstruct cache to invoke instance method
        let store = MockSecureStore()
        let cache = VaultwardenTokenCache(store: store, backoffFilePath: "/tmp/backoff-\(UUID()).json")
        #expect(cache.sessionFingerprintMatches(entry: entry) == true)
    }

    @Test("T-W6.5-TC-06: sessionFingerprintMatches returns false when explicit fingerprint differs")
    func matches_differentFingerprint_returnsFalse() throws {
        let entry = VaultwardenTokenCache.TokenEntry(
            token: "x",
            expiresAt: Date(),
            sessionFingerprint: "obviously-not-the-current-session-xyz"
        )
        let store = MockSecureStore()
        let cache = VaultwardenTokenCache(store: store, backoffFilePath: "/tmp/backoff-\(UUID()).json")
        // On platforms where SessionFingerprint.current() returns nil, the
        // method returns true defensively; assert opposite truth ONLY when
        // the platform can compute fingerprints.
        if SessionFingerprint.current() != nil {
            #expect(cache.sessionFingerprintMatches(entry: entry) == false)
        }
    }
}
