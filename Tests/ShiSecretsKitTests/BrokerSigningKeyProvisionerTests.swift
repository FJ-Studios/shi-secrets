// BrokerSigningKeyProvisionerTests.swift
// P0 — shi-secrets first-run signing-key bootstrap
// Backlog: 8cc9c1f0-32cb-418f-80d5-824b0abb339d
// Spec: features/signing-key-bootstrap-2026-07-02.md
//
// Locks in the provisioner contract: on a fresh install (no key file),
// generate a 32-byte Ed25519 seed at 0600. On an existing install,
// leave the file untouched. On a wrong-perms install, fix them to 0600.

import Foundation
import Testing
@testable import ShiSecretsKit

@Suite("BrokerSigningKeyProvisioner — first-run bootstrap (P0)")
struct BrokerSigningKeyProvisionerTests {

    private func makeTempDir(file: StaticString = #filePath, line: UInt = #line) throws -> URL {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("brokerd-provisioner-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private func mode(of url: URL) throws -> UInt16 {
        let attrs = try FileManager.default.attributesOfItem(atPath: url.path)
        return (attrs[.posixPermissions] as? NSNumber)?.uint16Value ?? 0
    }

    /// AC-1: fresh install → new 32-byte key, 0600 perms, .provisioned.
    @Test("provisionIfNeeded generates a 32-byte 0600 key when file is absent")
    func provisionsWhenAbsent() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let deterministicSeed = Data(repeating: 0xAB, count: 32)
        let outcome = try BrokerSigningKeyProvisioner.provisionIfNeeded(
            credentialsDir: dir,
            random: { deterministicSeed }
        )

        #expect(outcome == .provisioned)

        let keyURL = dir.appendingPathComponent("broker-signing-key")
        #expect(FileManager.default.fileExists(atPath: keyURL.path))

        let bytes = try Data(contentsOf: keyURL)
        #expect(bytes.count == 32, "seed must be exactly 32 bytes; got \(bytes.count)")
        #expect(bytes == deterministicSeed, "seed must be the injected random bytes byte-for-byte")

        let m = try mode(of: keyURL)
        #expect(m == 0o600, "file mode must be 0o600; got \(String(m, radix: 8))")
    }

    /// AC-2: existing install → key file left byte-for-byte unchanged, .alreadyPresent.
    @Test("provisionIfNeeded leaves an existing key untouched")
    func leavesExistingUntouched() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let keyURL = dir.appendingPathComponent("broker-signing-key")
        let preSeed = Data(repeating: 0xCD, count: 32)
        try preSeed.write(to: keyURL)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyURL.path)

        let outcome = try BrokerSigningKeyProvisioner.provisionIfNeeded(
            credentialsDir: dir,
            random: { Data(repeating: 0x00, count: 32) }  // would overwrite if called
        )

        #expect(outcome == .alreadyPresent)
        let bytes = try Data(contentsOf: keyURL)
        #expect(bytes == preSeed, "existing key bytes must not be touched")
    }

    /// AC-3: wrong-perms install → file mode fixed to 0600, bytes unchanged.
    @Test("provisionIfNeeded fixes wrong permissions on an existing key")
    func fixesPermissionsOnExisting() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let keyURL = dir.appendingPathComponent("broker-signing-key")
        let preSeed = Data(repeating: 0xEF, count: 32)
        try preSeed.write(to: keyURL)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: keyURL.path)

        let outcome = try BrokerSigningKeyProvisioner.provisionIfNeeded(
            credentialsDir: dir,
            random: { Data(repeating: 0x00, count: 32) }
        )

        // Still alreadyPresent (bytes kept) but perms should be corrected.
        #expect(outcome == .alreadyPresent)
        let m = try mode(of: keyURL)
        #expect(m == 0o600, "wrong perms must be fixed to 0o600; got \(String(m, radix: 8))")

        let bytes = try Data(contentsOf: keyURL)
        #expect(bytes == preSeed, "existing key bytes must not be touched even when fixing perms")
    }
}
