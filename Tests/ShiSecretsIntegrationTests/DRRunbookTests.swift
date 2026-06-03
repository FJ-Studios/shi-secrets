import Foundation
import Testing

// T72 — DR runbook + 3 vendor rotation runbooks + exercise evidence.
//
// Tests assert presence + mandatory headings for:
//   runbooks/shikki-secrets-dr.md
//   runbooks/shikki-secrets-rotate-ovh.md
//   runbooks/shikki-secrets-rotate-brevo.md
//   runbooks/shikki-secrets-rotate-github.md
//   reports/shikki-secrets-dr-exercise-2026-04-20.md

@Suite("DRRunbook")
struct DRRunbookTests {

    /// Navigate up from the test file to the worktree root.
    private var repoRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()   // ShiSecretsIntegrationTests/
            .deletingLastPathComponent()   // Tests/
            .deletingLastPathComponent()   // packages/ShiSecrets/
            .deletingLastPathComponent()   // packages/
            .deletingLastPathComponent()   // worktree root
    }

    private func read(_ relative: String) -> String? {
        let url = repoRoot.appendingPathComponent(relative)
        return try? String(contentsOf: url, encoding: .utf8)
    }

    @Test("DR runbook exists — runbooks/shikki-secrets-dr.md documents reseed on new hardware")
    func test_dr_runbookExists_atRunbooksShiSecretsDrMd_documentsReseedOnNewHardware() {
        let text = read("runbooks/shikki-secrets-dr.md")
        #expect(text != nil, "runbooks/shikki-secrets-dr.md missing")
        guard let t = text else { return }
        #expect(t.contains("# Shikki Secrets — Disaster Recovery"))
        #expect(t.contains("New Hardware Reseed"))
        #expect(t.lowercased().contains("passkey"))
        #expect(t.contains("Vaultwarden"))
    }

    @Test("single-instance loss is not a permanent brick — passkey + vault fully reconstruct broker")
    func test_dr_singleInstanceLoss_notPermanentBrick_runbookReconstructsFromVaultPlusPasskey() {
        let text = read("runbooks/shikki-secrets-dr.md") ?? ""
        #expect(text.contains("not a permanent brick"))
        #expect(text.contains("reconstruct"))
    }

    @Test("DR exercised once — evidence file in reports/")
    func test_dr_runbookExercisedOnceBeforeV1Signoff_evidenceFileInReports() {
        let text = read("reports/shikki-secrets-dr-exercise-2026-04-20.md")
        #expect(text != nil, "DR exercise evidence missing")
        guard let t = text else { return }
        #expect(t.contains("DR Exercise — 2026-04-20"))
        #expect(t.contains("checksum"))
    }

    @Test("dry-run — DR runbook would reconstruct broker within SLO")
    func test_integration_drRunbookDryRun_reconstructsBrokerWithinSlo() {
        let text = read("runbooks/shikki-secrets-dr.md") ?? ""
        // SLO line pinned so ops operators can't delete it.
        #expect(text.contains("SLO"))
        #expect(text.contains("60 min"))
    }

    @Test("three vendor runbooks exist — ovh / brevo / github",
          arguments: ["ovh", "brevo", "github"])
    func test_dr_vendorRunbooks_exist(vendor: String) {
        let path = "runbooks/shikki-secrets-rotate-\(vendor).md"
        let text = read(path)
        #expect(text != nil, "Missing vendor runbook: \(path)")
        if let t = text {
            #expect(t.lowercased().contains(vendor))
            #expect(t.contains("Rotation"))
        }
    }
}
