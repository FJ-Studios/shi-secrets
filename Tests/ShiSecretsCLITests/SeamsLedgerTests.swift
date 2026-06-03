import Foundation
@testable import ShiSecretsCLI
import ShiSecretsKit
import Testing

@Suite("SeamsLedger")
struct SeamsLedgerTests {

    @Test("seams ledger — renders golden seam rows — scrollable — snapshot")
    func test_tui_seamsLedger_rendersGoldenSeamRows_scrollable_snapshot() async throws {
        let writer = SeamsWriter()
        try await writer.append(
            signal: .hibp(breachId: "breach-2026-04-01"),
            secret: "OVH_APP_KEY",
            outcome: .rotated,
            ts: Date(timeIntervalSince1970: 1_777_000_000),
            notes: "auto-rotation within 60s"
        )
        try await writer.append(
            signal: .manifestSigFailed(manifestVersion: "v1.2"),
            secret: "mcp-manifest",
            outcome: .bypassed,
            ts: Date(timeIntervalSince1970: 1_777_003_600),
            notes: "pinned retained"
        )
        let rows = await writer.all()
        let rendered = SeamsLedgerView.render(rows)
        #expect(rendered.contains("── Golden Seam Ledger ──"))
        #expect(rendered.contains("OVH_APP_KEY"))
        #expect(rendered.contains("hibp(breach-2026-04-01)"))
        #expect(rendered.contains("mcp-manifest"))
        #expect(rendered.contains("manifest_sig_failed(v1.2)"))
        #expect(rendered.contains("rotated"))
        #expect(rendered.contains("bypassed"))
        // empty-ledger path
        let emptyRender = SeamsLedgerView.render([])
        #expect(emptyRender.contains("(ledger empty — no seams written)"))
    }
}
