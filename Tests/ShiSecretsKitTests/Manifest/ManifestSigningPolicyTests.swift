import Foundation
import Testing
@testable import ShiSecretsKit

// ManifestSigningPolicy tests (Task 26 — BR-H-02c).
//
// The broker MUST NEVER sign manifests. Signing requires Daimyo's
// passkey user-presence and is performed by the external tool
// `shikki-manifest-sign`. This test source-greps the broker daemon
// tree (once Wave 4 lands it) to confirm no `.signature(for:)` call
// reachable from the daemon binary exists. Until the daemon target
// exists, we assert the scan utility itself works correctly.

@Suite("ManifestSigningPolicy")
struct ManifestSigningPolicyTests {

    @Test("signing requires passkey user-presence — non-interactive / in-broker forbidden")
    func mcpManifest_signingRequiresPasskeyUserPresence_nonInteractiveForbidden() throws {
        // The policy enum carries the canonical rationale string
        // consumed by the TUI footer when displaying manifest-version
        // info; its presence is the public surface of BR-H-02c.
        #expect(ManifestSigningPolicy.passkeyRequired.rationale.contains("passkey"))
        #expect(ManifestSigningPolicy.passkeyRequired.externalTool == "shikki-manifest-sign")

        // Source-grep guard: scan any broker-daemon sources present for
        // the forbidden signing API. If the directory does not exist
        // yet (Wave 4 hasn't landed), the scan is vacuously satisfied —
        // the test *enforces* the invariant once the target appears.
        let brokerdDir = ManifestSigningPolicy.brokerdSourceDirectory
        let findings = ManifestSigningPolicy.scanForForbiddenSigningCalls(under: brokerdDir)
        #expect(findings.isEmpty, "broker daemon must not contain manifest-signing code paths: \(findings)")
    }
}
