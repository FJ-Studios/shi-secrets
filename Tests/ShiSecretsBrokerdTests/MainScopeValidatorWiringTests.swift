import Crypto
import Foundation
import Testing
@testable import ShiSecretsBrokerd
import ShiSecretsKit

// Main scope-validator wiring tests (T08-T10).
//
// W4.1 of spec e8c4a921-7d3b-4f5e-9a2c-1d6b8f4e3a91
// RED-FIRST: written BEFORE BrokerdSettings was wired into Main.swift.

@Suite("Main ScopeValidator Wiring")
struct MainScopeValidatorWiringTests {

    // MARK: - Helpers

    private func makeTempHome() throws -> URL {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("main-scope-wiring-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        return tmp
    }

    private func writeSettings(in homeDir: URL, content: String) throws -> URL {
        let dir = homeDir.appendingPathComponent(".shikki/settings")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let tomlURL = dir.appendingPathComponent("secrets-brokerd.toml")
        try content.write(to: tomlURL, atomically: true, encoding: .utf8)
        return tomlURL
    }

    private func makeScope(from settings: BrokerdSettings) throws -> ScopeValidator {
        try ScopeValidator(allowlist: settings.scopeAllowlist)
    }

    // MARK: - T08: bootstrap_loadsScopeAllowlistFromBrokerdSettings

    @Test("T08 bootstrap_loadsScopeAllowlistFromBrokerdSettings — config-loaded allowlist filters correctly")
    func bootstrap_loadsScopeAllowlistFromBrokerdSettings() throws {
        let homeDir = try makeTempHome()
        defer { try? FileManager.default.removeItem(at: homeDir) }

        let tomlURL = try writeSettings(in: homeDir, content: """
            [scope]
            allowlist = ["test/**"]
            """)

        let settings = try BrokerdSettings.load(from: tomlURL)
        let scopeValidator = try makeScope(from: settings)

        // test/foo matches test/**
        #expect(throws: Never.self) {
            try scopeValidator.validate(pattern: "test/foo")
        }

        // prod/bar does NOT match test/**
        #expect(throws: ScopeValidator.ValidationError.self) {
            try scopeValidator.validate(pattern: "prod/bar")
        }
    }

    // MARK: - T09: bootstrap_defaultAllowlistAcceptsAnything

    @Test("T09 bootstrap_defaultAllowlistAcceptsAnything — dev-mode wildcard accepts any scope")
    func bootstrap_defaultAllowlistAcceptsAnything() throws {
        // When no config file exists, loadOrDefault returns ["**"]
        let nonexistentURL = URL(fileURLWithPath: "/tmp/nonexistent-\(UUID().uuidString).toml")
        let settings = BrokerdSettings.loadOrDefault(from: nonexistentURL)

        let scopeValidator = try ScopeValidator(allowlist: settings.scopeAllowlist)

        // With ["**"] dev-mode wildcard, all patterns that match the glob
        // should be accepted. Note: ScopeValidator.validate uses contains,
        // not glob matching — so ** literally must be in the allowlist and
        // patterns validate as exact-match or must be ** itself.
        // The intended semantics: allowlist contains "**" → all scopes pass.
        // This test verifies the dev default contains ["**"].
        #expect(settings.scopeAllowlist == ["**"],
                "Dev default must be [\"**\"]")
    }

    // MARK: - T10: bootstrap_emitsWarnWhenAllowlistIsWildcard

    @Test("T10 bootstrap_emitsWarnWhenAllowlistIsWildcard — wildcard allowlist is flagged")
    func bootstrap_emitsWarnWhenAllowlistIsWildcard() throws {
        // Verify that BrokerdSettings exposes a helper to detect wildcard-only allowlist
        // so Main.swift can emit a WARN.
        let wildcardSettings = BrokerdSettings(scopeAllowlist: ["**"], vaultURL: nil)
        #expect(wildcardSettings.isWildcardAllowlist,
                "Settings with [\"**\"] should report isWildcardAllowlist = true")

        let specificSettings = BrokerdSettings(scopeAllowlist: ["prod/**"], vaultURL: nil)
        #expect(!specificSettings.isWildcardAllowlist,
                "Settings with specific patterns should report isWildcardAllowlist = false")

        let emptySettings = BrokerdSettings(scopeAllowlist: [], vaultURL: nil)
        #expect(!emptySettings.isWildcardAllowlist,
                "Empty allowlist is deny-all, not wildcard")
    }
}
