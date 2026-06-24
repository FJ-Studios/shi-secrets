import Foundation
@testable import ShiSecretsBrokerd
import Testing

// Bootstrap.readVaultURLFromTOML — unit tests for backlog item 5256133A
// Config-chain tier 1: ~/.shikki/settings/secrets-brokerd.toml [vault_url]

@Suite("Bootstrap.readVaultURLFromTOML")
struct BootstrapVaultURLTests {

    // MARK: - Helpers

    /// Create a temporary directory acting as a home directory.
    private func makeTempHome() throws -> URL {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("bootstrap-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        return tmp
    }

    private func writeSettings(in homeDir: URL, content: String) throws -> URL {
        let settingsDir = homeDir.appendingPathComponent(".shikki/settings")
        try FileManager.default.createDirectory(at: settingsDir, withIntermediateDirectories: true)
        let tomlURL = settingsDir.appendingPathComponent("secrets-brokerd.toml")
        try content.write(to: tomlURL, atomically: true, encoding: .utf8)
        return tomlURL
    }

    // MARK: - Tests

    @Test("Returns nil when TOML file does not exist")
    func readVaultURL_returnsNil_whenFileAbsent() throws {
        let homeDir = try makeTempHome()
        defer { try? FileManager.default.removeItem(at: homeDir) }

        let result = Bootstrap.readVaultURLFromTOML(homeDirectory: homeDir.path)
        #expect(result == nil, "No file → should return nil")
    }

    @Test("Returns vault_url value from TOML file")
    func readVaultURL_returnsValue_fromTOML() throws {
        let homeDir = try makeTempHome()
        defer { try? FileManager.default.removeItem(at: homeDir) }

        try writeSettings(in: homeDir, content: """
            # secrets-brokerd configuration
            vault_url = "https://custom.example.com"
            """)

        let result = Bootstrap.readVaultURLFromTOML(homeDirectory: homeDir.path)
        #expect(result == "https://custom.example.com", "Should parse vault_url from TOML")
    }

    @Test("Returns nil when TOML has no vault_url key")
    func readVaultURL_returnsNil_whenKeyAbsent() throws {
        let homeDir = try makeTempHome()
        defer { try? FileManager.default.removeItem(at: homeDir) }

        try writeSettings(in: homeDir, content: """
            # other settings only
            socket_path = "/tmp/brokerd.sock"
            """)

        let result = Bootstrap.readVaultURLFromTOML(homeDirectory: homeDir.path)
        #expect(result == nil, "Missing vault_url key → should return nil")
    }

    @Test("Strips surrounding quotes from vault_url value")
    func readVaultURL_stripsQuotes() throws {
        let homeDir = try makeTempHome()
        defer { try? FileManager.default.removeItem(at: homeDir) }

        try writeSettings(in: homeDir, content: "vault_url = 'https://vw.example.net'\n")

        let result = Bootstrap.readVaultURLFromTOML(homeDirectory: homeDir.path)
        #expect(result == "https://vw.example.net", "Single-quoted value should be unquoted")
    }

    @Test("Ignores comment lines beginning with #")
    func readVaultURL_ignoresComments() throws {
        let homeDir = try makeTempHome()
        defer { try? FileManager.default.removeItem(at: homeDir) }

        try writeSettings(in: homeDir, content: """
            # vault_url = "https://commented-out.example.com"
            vault_url = "https://real.example.com"
            """)

        let result = Bootstrap.readVaultURLFromTOML(homeDirectory: homeDir.path)
        #expect(result == "https://real.example.com", "Commented vault_url must be ignored")
    }

    @Test("Returns nil when vault_url value is empty string")
    func readVaultURL_returnsNil_whenValueEmpty() throws {
        let homeDir = try makeTempHome()
        defer { try? FileManager.default.removeItem(at: homeDir) }

        try writeSettings(in: homeDir, content: "vault_url = \"\"\n")

        let result = Bootstrap.readVaultURLFromTOML(homeDirectory: homeDir.path)
        #expect(result == nil, "Empty vault_url value → should return nil")
    }
}
