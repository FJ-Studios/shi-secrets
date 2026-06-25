import Foundation
import Testing
@testable import ShiSecretsBrokerd

// BrokerdSettings — unit tests for TOML config-loaded scope allowlist.
//
// W4.1 of spec e8c4a921-7d3b-4f5e-9a2c-1d6b8f4e3a91
// RED-FIRST: these tests were written BEFORE BrokerdSettings existed.
// Every test here was initially failing (RED) until BrokerdSettings was implemented.

@Suite("BrokerdSettings")
struct BrokerdSettingsTests {

    // MARK: - Helpers

    private func makeTempHome() throws -> URL {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("brokerd-settings-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        return tmp
    }

    private func writeSettings(in dir: URL, content: String) throws -> URL {
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let tomlURL = dir.appendingPathComponent("secrets-brokerd.toml")
        try content.write(to: tomlURL, atomically: true, encoding: .utf8)
        return tomlURL
    }

    private func settingsDir(in homeDir: URL) -> URL {
        homeDir.appendingPathComponent(".shikki/settings")
    }

    // MARK: - T01: load_parsesScopeAllowlistFromTOML

    @Test("T01 load_parsesScopeAllowlistFromTOML — parses [scope] allowlist from TOML")
    func load_parsesScopeAllowlistFromTOML() throws {
        let homeDir = try makeTempHome()
        defer { try? FileManager.default.removeItem(at: homeDir) }

        let dir = settingsDir(in: homeDir)
        let tomlURL = try writeSettings(in: dir, content: """
            [scope]
            allowlist = ["foo/**", "bar/*"]
            """)

        let settings = try BrokerdSettings.load(from: tomlURL)
        #expect(settings.scopeAllowlist == ["foo/**", "bar/*"],
                "Should parse both patterns in order")
    }

    // MARK: - T02: load_throwsWhenTOMLMalformed

    @Test("T02 load_throwsWhenTOMLMalformed — throws on malformed TOML")
    func load_throwsWhenTOMLMalformed() throws {
        let homeDir = try makeTempHome()
        defer { try? FileManager.default.removeItem(at: homeDir) }

        let dir = settingsDir(in: homeDir)
        let tomlURL = try writeSettings(in: dir, content: """
            [scope
            allowlist = [
            """)

        #expect(throws: (any Error).self, "Malformed TOML should throw") {
            _ = try BrokerdSettings.load(from: tomlURL)
        }
    }

    // MARK: - T03: load_returnsEmptyAllowlistWhenSectionAbsent

    @Test("T03 load_returnsEmptyAllowlistWhenSectionAbsent — empty allowlist when [scope] missing")
    func load_returnsEmptyAllowlistWhenSectionAbsent() throws {
        let homeDir = try makeTempHome()
        defer { try? FileManager.default.removeItem(at: homeDir) }

        let dir = settingsDir(in: homeDir)
        let tomlURL = try writeSettings(in: dir, content: """
            vault_url = "https://vw.example.com"
            """)

        let settings = try BrokerdSettings.load(from: tomlURL)
        #expect(settings.scopeAllowlist.isEmpty,
                "No [scope] section → scopeAllowlist should be empty")
    }

    // MARK: - T04: loadOrDefault_returnsSafeDefaultsWhenFileAbsent

    @Test("T04 loadOrDefault_returnsSafeDefaultsWhenFileAbsent — returns dev-friendly defaults")
    func loadOrDefault_returnsSafeDefaultsWhenFileAbsent() throws {
        let homeDir = try makeTempHome()
        defer { try? FileManager.default.removeItem(at: homeDir) }

        // Point at a non-existent file
        let tomlURL = homeDir.appendingPathComponent("nonexistent.toml")
        let settings = BrokerdSettings.loadOrDefault(from: tomlURL)
        #expect(settings.scopeAllowlist == ["**"],
                "Absent file → dev-friendly default allowlist [\"**\"]")
        #expect(settings.vaultURL == nil,
                "Absent file → vaultURL should be nil")
    }

    // MARK: - T05: writeDefaultIfMissing_seedsConfigWhenAbsent

    @Test("T05 writeDefaultIfMissing_seedsConfigWhenAbsent — writes default when file absent")
    func writeDefaultIfMissing_seedsConfigWhenAbsent() throws {
        let homeDir = try makeTempHome()
        defer { try? FileManager.default.removeItem(at: homeDir) }

        let dir = settingsDir(in: homeDir)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let tomlURL = dir.appendingPathComponent("secrets-brokerd.toml")

        #expect(!FileManager.default.fileExists(atPath: tomlURL.path),
                "Pre-condition: file must not exist")

        try BrokerdSettings.writeDefaultIfMissing(at: tomlURL)

        #expect(FileManager.default.fileExists(atPath: tomlURL.path),
                "File should be created")
        let content = try String(contentsOf: tomlURL, encoding: .utf8)
        #expect(content.contains("[scope]"),
                "Written file should contain [scope] section")
        #expect(content.contains("allowlist"),
                "Written file should contain allowlist key")
        #expect(content.contains("\"**\""),
                "Written file should contain ** wildcard entry")
    }

    // MARK: - T06: writeDefaultIfMissing_doesNotOverwriteExistingFile

    @Test("T06 writeDefaultIfMissing_doesNotOverwriteExistingFile — no-op when file exists")
    func writeDefaultIfMissing_doesNotOverwriteExistingFile() throws {
        let homeDir = try makeTempHome()
        defer { try? FileManager.default.removeItem(at: homeDir) }

        let dir = settingsDir(in: homeDir)
        let customContent = """
            [scope]
            allowlist = ["custom/**"]
            """
        let tomlURL = try writeSettings(in: dir, content: customContent)

        try BrokerdSettings.writeDefaultIfMissing(at: tomlURL)

        let afterContent = try String(contentsOf: tomlURL, encoding: .utf8)
        #expect(afterContent == customContent,
                "Existing file must NOT be overwritten")
    }

    // MARK: - T07: roundTrip_writeThenLoad

    @Test("T07 roundTrip_writeThenLoad — write defaults then load produces same allowlist")
    func roundTrip_writeThenLoad() throws {
        let homeDir = try makeTempHome()
        defer { try? FileManager.default.removeItem(at: homeDir) }

        let dir = settingsDir(in: homeDir)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let tomlURL = dir.appendingPathComponent("secrets-brokerd.toml")

        try BrokerdSettings.writeDefaultIfMissing(at: tomlURL)
        let settings = try BrokerdSettings.load(from: tomlURL)
        #expect(settings.scopeAllowlist == ["**"],
                "Round-trip: write default then load → allowlist [\"**\"]")
    }
}
