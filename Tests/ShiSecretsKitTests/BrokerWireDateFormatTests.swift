import XCTest
import Foundation
@testable import ShiSecretsKit

// W0 of spec e8c4a921-7d3b-4f5e-9a2c-1d6b8f4e3a91
// ISO 8601 RFC 3339 UTC — SINGLE SoT for broker-wire dates.
//
// Operator mandate 2026-06-24: "we don't care, I'm the only one to use it now
// so fucking kill it and have only one SoT!" — no backward compat, no Double-path.
//
// T-W0-01: encode produces ISO 8601 string (not Double)
// T-W0-02: decode accepts ISO 8601 string
// T-W0-03: decode THROWS on Double input  [RED until band-aid removed]
// T-W0-04: decode THROWS on null          [RED until distantPast fallback removed]
// T-W0-05: all serialization sites use .iso8601 dateEncodingStrategy
// T-W0-06: regression guard — no secondsSince1970 in non-JWT code

final class BrokerWireDateFormatTests: XCTestCase {

    // MARK: - Helpers

    /// Build a valid VaultEntryRef JSON string with the given raw last_rotated value fragment.
    private func jsonWith(lastRotated: String) -> Data {
        """
        {
            "name": "ovh:dns",
            "scope": "ovh.dns.read:example.com",
            "tier": "hot",
            "usage_state": "hot",
            "last_rotated": \(lastRotated),
            "rotation_due": "2026-06-25T08:30:00Z"
        }
        """.data(using: .utf8)!
    }

    private var isoDecoder: JSONDecoder {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }

    private var isoEncoder: JSONEncoder {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        return e
    }

    // MARK: - T-W0-01: encode produces ISO 8601 string for last_rotated

    func testEncodeProducesISO8601String() throws {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        var components = DateComponents()
        components.year = 2026
        components.month = 6
        components.day = 24
        components.hour = 8
        components.minute = 30
        components.second = 0
        let knownDate = calendar.date(from: components)!

        let entry = VaultEntryRef(
            name: "ovh:dns",
            scope: "ovh.dns.read:example.com",
            tier: .hot,
            usageState: .hot,
            lastRotated: knownDate,
            rotationDue: knownDate.addingTimeInterval(86400)
        )

        let data = try isoEncoder.encode(entry)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]

        // last_rotated MUST be a String, NOT a Double or Int
        let lastRotatedValue = json["last_rotated"]
        XCTAssertTrue(
            lastRotatedValue is String,
            "last_rotated must encode as an ISO 8601 String, got: \(String(describing: lastRotatedValue))"
        )

        let str = lastRotatedValue as! String
        // Must contain "T" and "Z" — ISO 8601 markers
        XCTAssertTrue(str.contains("T"), "ISO 8601 string must contain 'T' separator, got: \(str)")
        XCTAssertTrue(str.hasSuffix("Z") || str.contains("+"), "ISO 8601 string must end in Z or have offset, got: \(str)")
    }

    // MARK: - T-W0-02: decode accepts ISO 8601 string

    func testDecodeAcceptsISO8601String() throws {
        let data = jsonWith(lastRotated: "\"2026-06-24T08:30:00Z\"")
        let entry = try isoDecoder.decode(VaultEntryRef.self, from: data)

        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        let components = calendar.dateComponents([.year, .month, .day, .hour, .minute, .second], from: entry.lastRotated)
        XCTAssertEqual(components.year, 2026)
        XCTAssertEqual(components.month, 6)
        XCTAssertEqual(components.day, 24)
        XCTAssertEqual(components.hour, 8)
        XCTAssertEqual(components.minute, 30)
        XCTAssertEqual(components.second, 0)
    }

    // MARK: - T-W0-03: decode THROWS on Double input [RED until band-aid removed]

    func testDecodeThrowsOnDoubleInput() throws {
        // A Unix epoch double (e.g. 1750000000.0) must NOT silently decode.
        // After the band-aid is removed, JSONDecoder with .iso8601 strategy
        // will throw a DecodingError when it encounters a numeric value
        // where it expects an ISO 8601 string.
        let data = jsonWith(lastRotated: "1750000000.0")

        XCTAssertThrowsError(
            try isoDecoder.decode(VaultEntryRef.self, from: data),
            "Decoding a Double for last_rotated must throw — no backward compat per operator mandate"
        ) { error in
            XCTAssertTrue(
                error is DecodingError,
                "Expected DecodingError, got: \(error)"
            )
        }
    }

    // MARK: - T-W0-04: decode THROWS on null [RED until distantPast fallback removed]

    func testDecodeThrowsOnNullLastRotated() throws {
        // null last_rotated must throw — no distantPast fallback.
        // VaultEntryRef.lastRotated is non-optional (Date, not Date?).
        // After removing the custom init, standard Codable will throw on null.
        let data = jsonWith(lastRotated: "null")

        XCTAssertThrowsError(
            try isoDecoder.decode(VaultEntryRef.self, from: data),
            "Decoding null for last_rotated must throw — distantPast fallback removed per operator mandate"
        ) { error in
            XCTAssertTrue(
                error is DecodingError,
                "Expected DecodingError, got: \(error)"
            )
        }
    }

    // MARK: - T-W0-05: all serialization sites use .iso8601 dateEncodingStrategy

    func testAllSerializationSitesUseISO8601Encoding() throws {
        // Source-scan: walk Sources/ShiSecretsBrokerd/**/*.swift
        // Assert ZERO occurrences of dateEncodingStrategy = .secondsSince1970
        // Exception: JWT fields (dies_at, nbf, iat) in SBT context
        let sourceDirs = ["Sources/ShiSecretsBrokerd", "Sources/ShiSecretsKit"]
        let fileManager = FileManager.default

        // Find the repo root by looking for Package.swift
        guard let repoRoot = findRepoRoot() else {
            XCTFail("Could not locate repo root (Package.swift not found)")
            return
        }

        var violations: [String] = []
        for dir in sourceDirs {
            let dirURL = URL(fileURLWithPath: repoRoot).appendingPathComponent(dir)
            guard let enumerator = fileManager.enumerator(at: dirURL, includingPropertiesForKeys: nil) else {
                continue
            }
            for case let fileURL as URL in enumerator {
                guard fileURL.pathExtension == "swift" else { continue }
                // Skip JWT/SBT/Token exception files
                let filename = fileURL.lastPathComponent
                if filename.contains("JWT") || filename.contains("SBT") || filename.contains("Token") {
                    continue
                }
                let contents = (try? String(contentsOf: fileURL, encoding: .utf8)) ?? ""
                if contents.contains("dateEncodingStrategy = .secondsSince1970") {
                    violations.append(fileURL.path)
                }
            }
        }

        XCTAssertTrue(
            violations.isEmpty,
            "Found secondsSince1970 dateEncodingStrategy in non-JWT files: \(violations.joined(separator: ", "))"
        )
    }

    // MARK: - T-W0-06: regression guard — no secondsSince1970 in non-JWT code

    func testNoSecondsSince1970InNonJWTCode() throws {
        let sourceDirs = ["Sources/ShiSecretsBrokerd", "Sources/ShiSecretsKit"]
        let fileManager = FileManager.default

        guard let repoRoot = findRepoRoot() else {
            XCTFail("Could not locate repo root (Package.swift not found)")
            return
        }

        var violations: [String] = []
        for dir in sourceDirs {
            let dirURL = URL(fileURLWithPath: repoRoot).appendingPathComponent(dir)
            guard let enumerator = fileManager.enumerator(at: dirURL, includingPropertiesForKeys: nil) else {
                continue
            }
            for case let fileURL as URL in enumerator {
                guard fileURL.pathExtension == "swift" else { continue }
                let filename = fileURL.lastPathComponent
                // Exception list: JWT/SBT/Token files use RFC 7519 Unix integers
                if filename.contains("JWT") || filename.contains("SBT") || filename.contains("Token") {
                    continue
                }
                let contents = (try? String(contentsOf: fileURL, encoding: .utf8)) ?? ""
                if contents.contains("dateEncodingStrategy = .secondsSince1970") {
                    violations.append(fileURL.lastPathComponent)
                }
            }
        }

        XCTAssertTrue(
            violations.isEmpty,
            "Regression: found secondsSince1970 in non-JWT source files: \(violations.joined(separator: ", "))"
        )
    }

    // MARK: - Private helpers

    /// Walk up from the test bundle to find the repo root (contains Package.swift).
    private func findRepoRoot() -> String? {
        // Strategy 1: look for PACKAGE_DIR env var set by swift test
        if let pkgDir = ProcessInfo.processInfo.environment["PACKAGE_DIR"] {
            return pkgDir
        }
        // Strategy 2: walk up from the test bundle's executableURL
        var url = Bundle(for: type(of: self)).bundleURL
        for _ in 0..<8 {
            let candidate = url.appendingPathComponent("Package.swift")
            if FileManager.default.fileExists(atPath: candidate.path) {
                return url.path
            }
            url = url.deletingLastPathComponent()
        }
        return nil
    }
}
