import Foundation
import XCTest

// AdminKeyCeremonyEntitlementsTests
//
// Linux-skippable (macOS Keychain is macOS-only). Tests the static shape
// of the entitlements plist and confirms the codesign script exists and
// is executable. Does NOT invoke codesign (requires a Developer ID cert).
//
// Phase 0.5-fix (BR-G-06) — 2026-05-23.

final class AdminKeyCeremonyEntitlementsTests: XCTestCase {

    // MARK: - Helpers

    /// Resolve the monorepo root by walking up from this file's compile-time
    /// path until we find `packages/ShiSecrets/Package.swift`.
    private static func repoRoot() throws -> URL {
        // __FILE__ is resolved at compile time to the source file path.
        // In an SPM test binary this gives us a stable anchor into the repo.
        var candidate = URL(fileURLWithPath: #filePath)
        for _ in 0..<12 {
            candidate = candidate.deletingLastPathComponent()
            let probe = candidate
                .appendingPathComponent("packages/ShiSecrets/Package.swift")
            if FileManager.default.fileExists(atPath: probe.path) {
                return candidate
            }
        }
        throw XCTSkip("Cannot locate repo root from \(#filePath) — skipping.")
    }

    // MARK: - Plist shape tests

    func testEntitlementsPlistExists() throws {
        #if os(Linux)
        throw XCTSkip("Keychain entitlements are macOS-only")
        #endif
        let root = try Self.repoRoot()
        let plistPath = root
            .appendingPathComponent(
                "packages/ShiSecrets/Sources/AdminKeyCeremony/AdminKeyCeremony.entitlements")
            .path
        XCTAssertTrue(
            FileManager.default.fileExists(atPath: plistPath),
            "Entitlements plist missing at \(plistPath)")
    }

    func testEntitlementsPlistIsValidPlist() throws {
        #if os(Linux)
        throw XCTSkip("Keychain entitlements are macOS-only")
        #endif
        let root = try Self.repoRoot()
        let plistURL = root
            .appendingPathComponent(
                "packages/ShiSecrets/Sources/AdminKeyCeremony/AdminKeyCeremony.entitlements")
        let data = try Data(contentsOf: plistURL)
        var format = PropertyListSerialization.PropertyListFormat.xml
        let plist = try PropertyListSerialization.propertyList(
            from: data, options: [], format: &format)
        XCTAssertEqual(format, .xml, "Entitlements plist must be XML format")
        guard let dict = plist as? [String: Any] else {
            XCTFail("Entitlements plist root must be a dictionary")
            return
        }
        XCTAssertNotNil(dict["keychain-access-groups"],
            "Entitlements plist must contain keychain-access-groups key")
    }

    func testEntitlementsPlistKeychainGroupShape() throws {
        #if os(Linux)
        throw XCTSkip("Keychain entitlements are macOS-only")
        #endif
        let root = try Self.repoRoot()
        let plistURL = root
            .appendingPathComponent(
                "packages/ShiSecrets/Sources/AdminKeyCeremony/AdminKeyCeremony.entitlements")
        let data = try Data(contentsOf: plistURL)
        var format = PropertyListSerialization.PropertyListFormat.xml
        let plist = try PropertyListSerialization.propertyList(
            from: data, options: [], format: &format)
        let dict = plist as! [String: Any]
        let groups = dict["keychain-access-groups"] as? [String]
        XCTAssertNotNil(groups, "keychain-access-groups must be an array of strings")
        XCTAssertFalse(groups?.isEmpty ?? true, "keychain-access-groups must not be empty")
        // The group must reference the shikki admin service ID.
        // W3.1: canonical bundle prefix is io.shikki.* (product domain mandate).
        // The assertion checks for "shikki.admin" substring which matches both
        // the new io.shikki.admin-key-ceremony and any future io.shikki.admin* identifiers.
        let hasAdminGroup = groups?.contains(where: { $0.contains("shikki.admin") }) ?? false
        XCTAssertTrue(hasAdminGroup,
            "keychain-access-groups must include shikki.admin, got: \(groups ?? [])")
    }

    // MARK: - Codesign script tests

    func testCodesignScriptExists() throws {
        #if os(Linux)
        throw XCTSkip("Codesign is macOS-only")
        #endif
        let root = try Self.repoRoot()
        let scriptPath = root
            .appendingPathComponent("scripts/codesign-admin-key-ceremony.sh")
            .path
        XCTAssertTrue(
            FileManager.default.fileExists(atPath: scriptPath),
            "Codesign script missing at \(scriptPath)")
    }

    func testCodesignScriptIsExecutable() throws {
        #if os(Linux)
        throw XCTSkip("Codesign is macOS-only")
        #endif
        let root = try Self.repoRoot()
        let scriptPath = root
            .appendingPathComponent("scripts/codesign-admin-key-ceremony.sh")
            .path
        let attrs = try FileManager.default.attributesOfItem(atPath: scriptPath)
        let perms = (attrs[.posixPermissions] as? Int) ?? 0
        // At minimum, owner-execute bit (0o100) must be set.
        XCTAssertTrue(perms & 0o100 != 0,
            "Codesign script must be executable (owner+x). Got permissions: \(String(perms, radix: 8))")
    }
}
