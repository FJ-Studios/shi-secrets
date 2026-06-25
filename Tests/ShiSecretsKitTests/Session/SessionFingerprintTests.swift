// SessionFingerprintTests — W6.5
//
// Pure-Swift unit tests for the SessionFingerprint helper. Platform-specific
// behavior (sysctl on Mac, loginctl on Linux) is covered by @Integration
// tests in BrokerDaemonSessionLifecycleTests; here we test the contract:
//
//   • `.current()` returns SOMETHING on macOS (sysctl always works)
//   • returned string has the documented format (starts with `mac:` or `linux:`)
//   • two consecutive calls in the same process return the SAME string
//     (fingerprint must be deterministic within a session)
//   • length is bounded
//
// Spec UUID: e8c4a921-7d3b-4f5e-9a2c-1d6b8f4e3a91 (W6.5)

import Testing
import Foundation
@testable import ShiSecretsKit

@Suite("SessionFingerprint W6.5")
struct SessionFingerprintTests {

    @Test("T-W6.5-FP-01: current() returns non-empty on macOS")
    func current_returnsNonEmpty_onMac() throws {
        #if os(macOS)
        let fp = SessionFingerprint.current()
        #expect(fp != nil)
        #expect(!(fp ?? "").isEmpty)
        #else
        // On Linux, requires XDG_SESSION_ID + loginctl; skip in unit suite.
        try Issue.record("Linux fingerprint requires real session env; covered by @Integration")
        #endif
    }

    @Test("T-W6.5-FP-02: format prefix is platform-tagged")
    func format_prefixIsPlatformTagged() throws {
        let fp = SessionFingerprint.current() ?? ""
        #if os(macOS)
        #expect(fp.hasPrefix("mac:"))
        #elseif os(Linux)
        #expect(fp.hasPrefix("linux:") || fp.isEmpty)  // empty acceptable in CI without session
        #endif
    }

    @Test("T-W6.5-FP-03: deterministic — two consecutive calls return same fingerprint")
    func deterministic_twoConsecutiveCalls_sameValue() throws {
        let a = SessionFingerprint.current()
        let b = SessionFingerprint.current()
        #expect(a == b)
    }

    @Test("T-W6.5-FP-04: length bounded (≤256 chars)")
    func length_bounded() throws {
        let fp = SessionFingerprint.current() ?? ""
        #expect(fp.count <= 256)
    }

    #if os(macOS)
    @Test("T-W6.5-FP-05: macOSBoottimeUnix returns reasonable value")
    func macOSBoottimeUnix_reasonable() throws {
        let boot = SessionFingerprint.macOSBoottimeUnix()
        #expect(boot != nil)
        let now = Int(Date().timeIntervalSince1970)
        // Boot must be in the past, but not before 2020-01-01 (sanity)
        #expect((boot ?? 0) < now)
        #expect((boot ?? 0) > 1_577_836_800)  // 2020-01-01 UTC
    }
    #endif
}
