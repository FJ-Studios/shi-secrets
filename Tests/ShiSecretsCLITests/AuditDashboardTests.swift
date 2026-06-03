import Foundation
@testable import ShiSecretsCLI
import Testing

@Suite("AuditDashboard")
struct AuditDashboardTests {

    // T62 — headline numbers pinned.
    @Test("audit dashboard — renders 3 headline numbers (stale / llm_touched unrotated / denied 24h)")
    func test_tui_auditSecretsDashboard_rendersThreeHeadlineNumbers_staleLlmTouchedUnrotatedDenied24h() {
        let ctx = AuditDashboardContext(
            hostName: "nuc-dev",
            brokerVersion: "v1.0",
            nowClock: "13:42",
            staleCount: 0,
            llmTouchedUnrotated: 0,
            denied24h: 0,
            rows: [],
            footerLine: "● all healthy · 0 anomalies",
            state: .healthy
        )
        let rendered = AuditDashboard.render(ctx)
        #expect(rendered.contains("stale 0"))
        #expect(rendered.contains("llm-touched unrotated 0"))
        #expect(rendered.contains("denied 24h 0"))
    }

    // T62 — state derivation, parameterized.
    @Test("state derivation — healthy / llmInFlight / incident",
          arguments: [
            (stale: 0, llm: 0, deny: 0, want: DashboardState.healthy),
            (stale: 0, llm: 3, deny: 0, want: DashboardState.llmInFlight),
            (stale: 3, llm: 1, deny: 5, want: DashboardState.incident),
          ])
    func test_tui_auditSecretsDashboard_colorizedTimelineStates(
        stale: Int, llm: Int, deny: Int, want: DashboardState
    ) {
        let got = AuditDashboard.deriveState(
            stale: stale,
            llmTouchedUnrotated: llm,
            denied24h: deny
        )
        #expect(got == want)
    }

    // T62 — healthy state — green footer + at least one blue (warm) row.
    // Review finding #12 — migrated to RowKind enum initializer.
    @Test("healthy state — visibly healthy — footer all healthy · 0 anomalies — snapshot")
    func test_tui_auditSecretsDashboard_healthyState_visiblyHealthy_snapshot() {
        let rows: [DashboardRow] = [
            DashboardRow(time: "13:41", kind: .warm, secret: "OVH_APP_KEY", op: "read"),
            DashboardRow(time: "13:38", kind: .warm, secret: "BREVO_SMTP ", op: "read"),
            DashboardRow(time: "12:55", kind: .cool, secret: "GH_PAT_BACK", op: "read"),
            DashboardRow(time: "11:12", kind: .ext,  secret: "APPLE_DEV  ", op: "read"),
        ]
        let ctx = AuditDashboardContext(
            hostName: "nuc-dev",
            brokerVersion: "v1.0",
            nowClock: "13:42",
            staleCount: 0,
            llmTouchedUnrotated: 0,
            denied24h: 0,
            rows: rows,
            footerLine: "● all healthy · 0 anomalies",
            state: .healthy
        )
        let rendered = AuditDashboard.render(ctx)
        #expect(rendered.contains("● all healthy · 0 anomalies"))
        // All four timeline rows must appear.
        for r in rows {
            #expect(rendered.contains(r.time))
        }
    }

    // T62 — keybind line at the bottom.
    @Test("keybind line — r rotate · R revoke · / filter · q quit")
    func test_tui_auditSecretsDashboard_keybinds_rRotate_RRevoke_slashFilter_qQuit() {
        #expect(AuditDashboard.keybindLine == "r rotate · R revoke · / filter · q quit")
        // Also assert the line appears in the rendered frame.
        let ctx = AuditDashboardContext(
            hostName: "nuc-dev", brokerVersion: "v1.0", nowClock: "00:00",
            staleCount: 0, llmTouchedUnrotated: 0, denied24h: 0,
            rows: [], footerLine: "", state: .healthy
        )
        let rendered = AuditDashboard.render(ctx)
        #expect(rendered.contains("r rotate · R revoke · / filter · q quit"))
    }

    // Review finding #9 — State 2 mockup snapshot (Phase 5a).
    // 1 llm-touched unrotated, amber top bar, magenta (llm) markers.
    @Test("llmInFlight state — 1 llm-touched unrotated, magenta markers — snapshot")
    func test_tui_auditSecretsDashboard_state2_llmInFlight_snapshot() {
        let rows: [DashboardRow] = [
            DashboardRow(time: "14:06", kind: .llm,  secret: "OVH_APP_KEY",   op: "read"),
            DashboardRow(time: "14:05", kind: .llm,  secret: "OVH_DNS_ZONE",  op: "read"),
            DashboardRow(time: "14:03", kind: .warm, secret: "BREVO_SMTP",    op: "read"),
            DashboardRow(time: "13:41", kind: .cool, secret: "GH_PAT_BACKUP", op: "read"),
        ]
        let ctx = AuditDashboardContext(
            hostName: "nuc-dev",
            brokerVersion: "v1.0",
            nowClock: "14:07",
            staleCount: 0,
            llmTouchedUnrotated: 1,
            denied24h: 0,
            rows: rows,
            footerLine: "◉ llm_touched: parent rotates within 60m of SessionEnd",
            state: .llmInFlight
        )
        let rendered = AuditDashboard.render(ctx)
        // State-2 headline numbers.
        #expect(rendered.contains("stale 0"))
        #expect(rendered.contains("llm-touched unrotated 1"))
        #expect(rendered.contains("denied 24h 0"))
        // State-2 footer + llm markers (magenta, ◉-style glyph carried
        // by RowKind.llm).
        #expect(rendered.contains("◉ llm_touched"))
        // Every llm-kind row is rendered with the `llm ` marker vocab.
        for r in rows where r.kind == .llm {
            #expect(rendered.contains(r.time))
            #expect(rendered.contains("llm "))
        }
        // RowKind.llm must resolve magenta per the vocabulary-lock.
        #expect(DashboardRow.RowKind.llm.color == .magenta)
    }

    // Review finding #9 — State 3 mockup snapshot (Phase 5a).
    // 3 stale / 1 llm / 5 denied; red markers + scope_pattern_denied detail.
    @Test("incident state — 3 stale, 5 denied, seams row + scope_pattern_denied — snapshot")
    func test_tui_auditSecretsDashboard_state3_incident_snapshot() {
        let rows: [DashboardRow] = [
            DashboardRow(time: "14:57", kind: .deny, secret: "HETZNER_CLOUD", op: "read"),
            DashboardRow(time: "14:56", kind: .seam, secret: "OVH_APP_KEY",   op: "rot "),
            DashboardRow(time: "14:55", kind: .deny, secret: "HETZNER_CLOUD", op: "read"),
            DashboardRow(time: "14:54", kind: .deny, secret: "AWS_LEGACY",    op: "read"),
            DashboardRow(time: "14:52", kind: .deny, secret: "HETZNER_CLOUD", op: "read"),
            DashboardRow(time: "14:49", kind: .deny, secret: "GCP_LEGACY",    op: "read"),
            DashboardRow(time: "14:40", kind: .llm,  secret: "OVH_APP_KEY",   op: "read"),
            DashboardRow(time: "14:12", kind: .warm, secret: "BREVO_SMTP",    op: "read"),
        ]
        let ctx = AuditDashboardContext(
            hostName: "nuc-dev",
            brokerVersion: "v1.0",
            nowClock: "14:58",
            staleCount: 3,
            llmTouchedUnrotated: 1,
            denied24h: 5,
            rows: rows,
            footerLine: "◆ seams: hibp match on OVH_APP_KEY — reason scope_pattern_denied",
            state: .incident
        )
        let rendered = AuditDashboard.render(ctx)
        // State-3 headline numbers.
        #expect(rendered.contains("stale 3"))
        #expect(rendered.contains("llm-touched unrotated 1"))
        #expect(rendered.contains("denied 24h 5"))
        // scope_pattern_denied reason surfaced verbatim in the detail line.
        #expect(rendered.contains("scope_pattern_denied"))
        // Seam marker + deny rows drawn.
        #expect(rendered.contains("seam"))
        #expect(rendered.contains("deny"))
        // RowKind vocabulary lock: ✕ + ◆ color to .red.
        #expect(DashboardRow.RowKind.deny.color == .red)
        #expect(DashboardRow.RowKind.seam.color == .red)
    }
}
