import Foundation
import Testing
@testable import ShiSecretsKit

// AnomalySignal enum tests (Task 8 — BR-B-07, BR-C-08, BR-H-02d).
// All six anomaly classes must be representable, Codable, Equatable, and
// carry a machine-readable payload for the downstream rotation engine.

@Suite("AnomalySignal")
struct AnomalySignalTests {

    @Test("AnomalySignal exposes all six cases with their payloads")
    func allSixCasesPresent() throws {
        let signals: [AnomalySignal] = [
            .hibp(breachId: "breach-42"),
            .unexpectedIP(ip: "203.0.113.9", secretName: "ovh:dns"),
            .failedFetchBurst(windowSec: 60, count: 12, secretName: "brevo:api"),
            .vendorBreach(vendor: "github", advisoryURL: "https://example/advisory"),
            .selfRevokeMissed(jti: "01JABCDEF", secretName: "ovh:dns"),
            .manifestSigFailed(manifestVersion: "v3"),
        ]

        // Six distinct cases.
        #expect(signals.count == 6)

        // Roundtrip through JSON (Codable) survives every case.
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()
        for original in signals {
            let data = try encoder.encode(original)
            let decoded = try decoder.decode(AnomalySignal.self, from: data)
            #expect(decoded == original, "Roundtrip changed value for \(original)")
        }

        // Distinct cases are not equal to each other.
        for (lhsIndex, lhs) in signals.enumerated() {
            for (rhsIndex, rhs) in signals.enumerated() where rhsIndex != lhsIndex {
                #expect(lhs != rhs, "\(lhs) and \(rhs) should not compare equal")
            }
        }
    }
}
