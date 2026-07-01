// PatternDetectorTests — T-W6.5c-07 / T-W6.5c-08 (per spec W6.5c GREEN list).
//
// PatternDetector selects the per-system identity deployment pattern by probing
// the server's capability surface:
//   Pattern A — Bitwarden Secrets Manager machine_accounts (client_credentials
//               grant + Project scopes). Selected when the server exposes the
//               Secrets Manager API.
//   Pattern B — per-USER Bitwarden accounts on stock Vaultwarden (default today).
//               Fallback when Secrets Manager is absent.
// (Pattern C — Hanko-issued tokens — is opt-in via --via-hanko, NOT auto-detected.)
//
// Mapping to spec test IDs:
//   T-W6.5c-07 → secretsManagerAvailable_selectsPatternA
//   T-W6.5c-08 → stockVaultwarden_fallsBackToPatternB
//
// The network probe is abstracted behind VaultCapabilityProbe so these tests do
// zero network I/O.

import Foundation
import Testing
@testable import ShiSecretsKit

/// Test double for the capability probe — returns a fixed answer.
private struct StubProbe: VaultCapabilityProbe {
    let available: Bool
    func secretsManagerAvailable() async -> Bool { available }
}

@Suite("W6.5c PatternDetector — A/B auto-detection")
struct PatternDetectorTests {

    // T-W6.5c-07
    @Test("Secrets Manager available → selects Pattern A")
    func secretsManagerAvailable_selectsPatternA() async {
        let detector = PatternDetector(probe: StubProbe(available: true))
        let pattern = await detector.detect()
        #expect(pattern == .a)
    }

    // T-W6.5c-08
    @Test("stock Vaultwarden (no Secrets Manager) → falls back to Pattern B")
    func stockVaultwarden_fallsBackToPatternB() async {
        let detector = PatternDetector(probe: StubProbe(available: false))
        let pattern = await detector.detect()
        #expect(pattern == .b)
    }

    @Test("DeploymentPattern wire values are stable (a/b)")
    func wireValuesStable() {
        #expect(DeploymentPattern.a.rawValue == "a")
        #expect(DeploymentPattern.b.rawValue == "b")
    }
}
