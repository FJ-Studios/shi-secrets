// ScopeBlastRadiusDeniedReasonTests — v0.5.0 Wave A3 regression guard
// for the new AuditRow.DenyReason case distinguishing toml-allowlist
// deny (.scopePatternDenied) from per-system blast-radius deny
// (.scopeBlastRadiusDenied). @sensei v0.4.2 panel finding.
//
// AC-A3-01: enum case exists and serializes to snake_case wire string
// AC-A3-02: distinct from .scopePatternDenied at the value level
// AC-A3-03: round-trips through Codable (machine-readable audit row)
// AC-A3-04: CaseIterable surface includes both cases (consumers must
//           handle the new case explicitly — exhaustive switches break
//           at compile-time which is exactly the desired contract)

import Foundation
import Testing
@testable import ShiSecretsKit

@Suite("Wave A3 — scopeBlastRadiusDenied audit reason")
struct ScopeBlastRadiusDeniedReasonTests {

    @Test("AC-A3-01: case exists with canonical snake_case raw value")
    func canonicalRawValue() {
        #expect(AuditRow.DenyReason.scopeBlastRadiusDenied.rawValue == "scope_blast_radius_denied")
    }

    @Test("AC-A3-02: distinct from .scopePatternDenied")
    func distinctFromPatternDenied() {
        let blast: AuditRow.DenyReason = .scopeBlastRadiusDenied
        let pattern: AuditRow.DenyReason = .scopePatternDenied
        #expect(blast != pattern)
        #expect(blast.rawValue != pattern.rawValue)
    }

    @Test("AC-A3-03: round-trips through Codable")
    func roundTripsCodable() throws {
        let row = AuditRow(
            ts: Date(timeIntervalSince1970: 1_700_000_000),
            tokenJti: "wave-a3-blast",
            callerUid: 1001,
            callerTransport: .unix,
            secretName: "shi/system/other-machine/openai",
            op: .read,
            allow: .deny,
            reason: .scopeBlastRadiusDenied,
            llmTouched: false
        )
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys]
        let data = try enc.encode(row)
        let raw = String(data: data, encoding: .utf8) ?? ""
        #expect(raw.contains("scope_blast_radius_denied"))

        let decoded = try JSONDecoder().decode(AuditRow.self, from: data)
        #expect(decoded.reason == .scopeBlastRadiusDenied)
    }

    @Test("AC-A3-04: CaseIterable includes both scope-deny cases")
    func caseIterableIncludesBoth() {
        let all = AuditRow.DenyReason.allCases
        #expect(all.contains(.scopePatternDenied))
        #expect(all.contains(.scopeBlastRadiusDenied))
    }
}
