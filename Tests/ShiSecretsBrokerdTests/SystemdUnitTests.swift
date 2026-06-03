import Foundation
@testable import ShiSecretsBrokerd
import Testing

@Suite("SystemdUnit")
struct SystemdUnitTests {

    /// Walks up from Bundle.module (Tests/…) to the repo root, then reads
    /// `deploy/nuc-dev/systemd/*`. The deploy files are checked-in
    /// plain text; no bundle resource copy needed.
    private func deployDir() -> URL {
        let file = URL(fileURLWithPath: #filePath)
        // .../packages/ShiSecrets/Tests/ShiSecretsBrokerdTests/SystemdUnitTests.swift
        //           5     4                 3                        2              1
        return file
            .deletingLastPathComponent()   // ShiSecretsBrokerdTests
            .deletingLastPathComponent()   // Tests
            .deletingLastPathComponent()   // ShiSecrets
            .deletingLastPathComponent()   // packages
            .deletingLastPathComponent()   // worktree root
            .appendingPathComponent("deploy/nuc-dev/systemd", isDirectory: true)
    }

    @Test("single shikki-kerneld.service unit; no timer files anywhere under deploy/nuc-dev/systemd")
    func test_systemdUnit_singleKerneldUnit_noTimerFiles() throws {
        let dir = deployDir()
        let unit = dir.appendingPathComponent("shikki-kerneld.service")
        #expect(FileManager.default.fileExists(atPath: unit.path))

        // Walk deploy/nuc-dev/systemd/ recursively; refuse any `.timer` file.
        if let enumerator = FileManager.default.enumerator(atPath: dir.path) {
            for case let path as String in enumerator {
                #expect(!path.hasSuffix(".timer"), "found unexpected .timer: \(path)")
            }
        }
    }

    @Test("drop-in file: bw-session removed (W1), broker-signing-key retained")
    func test_systemdUnit_loadCredentialEncryptedBwSession_present() throws {
        // W1 (shi-secrets W1 — 2026-05-21): bw-session credential REMOVED.
        // Vaultwarden credentials now live in macOS Keychain.
        // The broker-signing-key credential is retained for Linux.
        let dir = deployDir()
        let dropIn = dir
            .appendingPathComponent("shikki-kerneld.service.d", isDirectory: true)
            .appendingPathComponent("10-credentials.conf")
        let contents = try String(contentsOf: dropIn, encoding: .utf8)
        // bw-session must NOT appear in W1+.
        #expect(!contents.contains("LoadCredentialEncrypted=bw-session:"),
                "bw-session credential removed in W1 — Keychain replaces it")
        // broker-signing-key must still be present.
        #expect(contents.contains("LoadCredentialEncrypted=broker-signing-key:"),
                "broker-signing-key credential retained in W1")
        // The main unit must pin User=shikki-broker (system-level hardening).
        let unitContents = try String(
            contentsOf: dir.appendingPathComponent("shikki-kerneld.service"),
            encoding: .utf8
        )
        #expect(unitContents.contains("User=shikki-broker"))
    }
}
