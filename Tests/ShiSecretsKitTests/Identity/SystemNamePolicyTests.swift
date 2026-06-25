// SystemNamePolicyTests — TP-W6.5c-03 / TP-W6.5c-04 (per spec amendment 2026-06-25).
//
// Validates the per-system name policy that drives Bitwarden collection scoping.
//
// Mapping to spec test IDs:
//   T-W6.5c-03 → defaultName_isHostnameUnderscoreShikki
//   T-W6.5c-04 → validate_alphanumDashOnly_lengthBounded

import Foundation
import Testing
@testable import ShiSecretsKit

@Suite("W6.5c SystemNamePolicy — validation contract")
struct SystemNamePolicyValidationTests {

    @Test("happy path — lowercase alphanumeric + dashes is valid")
    func happy() {
        let r = SystemNamePolicy.validate("mac-laptop-shikki")
        #expect((try? r.get()) == .some("mac-laptop-shikki"))
    }

    @Test("uppercase is canonicalised to lowercase")
    func canonicalisesLowercase() {
        let r = SystemNamePolicy.validate("Mac-Laptop")
        #expect((try? r.get()) == .some("mac-laptop"))
    }

    @Test("empty string is rejected")
    func rejectsEmpty() {
        if case .failure(let e) = SystemNamePolicy.validate("") {
            #expect(e == .empty)
        } else {
            Issue.record("expected .failure(.empty)")
        }
    }

    @Test("32-char name is permitted; 33-char is rejected")
    func rejectsTooLong() {
        let okName = String(repeating: "a", count: 32)
        #expect((try? SystemNamePolicy.validate(okName).get()) == .some(okName))
        let tooLong = String(repeating: "a", count: 33)
        if case .failure(let e) = SystemNamePolicy.validate(tooLong) {
            #expect(e == .tooLong(max: 32))
        } else { Issue.record("expected too-long failure") }
    }

    @Test("invalid character (underscore) is rejected with the offending scalar")
    func rejectsUnderscore() {
        if case .failure(let e) = SystemNamePolicy.validate("mac_laptop") {
            if case .invalidCharacter(let s) = e {
                #expect(s == "_")
            } else { Issue.record("expected .invalidCharacter") }
        } else { Issue.record("expected failure") }
    }

    @Test("leading dash is rejected")
    func rejectsLeadingDash() {
        if case .failure(let e) = SystemNamePolicy.validate("-mac") {
            #expect(e == .mustStartWithAlphanumeric)
        } else { Issue.record("expected mustStartWithAlphanumeric") }
    }

    @Test("trailing dash is rejected")
    func rejectsTrailingDash() {
        if case .failure(let e) = SystemNamePolicy.validate("mac-") {
            #expect(e == .mustEndWithAlphanumeric)
        } else { Issue.record("expected mustEndWithAlphanumeric") }
    }

    @Test("consecutive dashes are rejected")
    func rejectsDoubleDash() {
        if case .failure(let e) = SystemNamePolicy.validate("mac--laptop") {
            #expect(e == .consecutiveDashes)
        } else { Issue.record("expected consecutiveDashes") }
    }
}

@Suite("W6.5c SystemNamePolicy — default derivation")
struct SystemNamePolicyDefaultTests {

    @Test("hostname.local becomes <hostname>-shikki")
    func dotLocalStripped() {
        let d = SystemNamePolicy.defaultName(hostname: "MacBook-Pro.local")
        #expect(d == "macbook-pro-shikki")
    }

    @Test("simple hostname appends -shikki")
    func appendsShikki() {
        let d = SystemNamePolicy.defaultName(hostname: "nuc-dev")
        #expect(d == "nuc-dev-shikki")
    }

    @Test("very long hostname is trimmed to fit max-length")
    func trimsToFit() {
        let d = SystemNamePolicy.defaultName(hostname: String(repeating: "a", count: 60))
        #expect(d.count <= SystemNamePolicy.maxLength)
        #expect(d.hasSuffix("-shikki"))
    }

    @Test("empty hostname falls back to 'shikki'")
    func emptyHostnameFallback() {
        let d = SystemNamePolicy.defaultName(hostname: "")
        #expect(d == "shikki")
    }
}
