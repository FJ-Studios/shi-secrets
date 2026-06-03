import Foundation
@testable import ShiSecretsCLI
import ShiSecretsClient
import Testing

@Suite("TwoChannelConfirm")
struct TwoChannelConfirmTests {

    @Test("rotate success — terminal fingerprint pair (old …a3f2 invalid since HH:MM:SS CET)")
    func test_cli_rotateSuccess_twoChannelConfirmation_terminalFingerprintPair_snapshot() {
        // Fixed UTC timestamp: 2026-05-05 14:55:23 UTC → 16:55:23 Europe/Paris (CEST, DST).
        // Review finding #10 — renderer now formats in the target TZ
        // instead of UTC-with-CET-label. Expected rendering moves from
        // 14:55:23 (UTC, previously-mislabelled-as-CET) to 16:55:23 (actual Paris local time).
        let invalidAt = Date(timeIntervalSince1970: 1_777_992_923)
        let result = RotationResult(
            secretName: "OVH_APP_KEY",
            oldJtiSuffix: "a3f2",
            invalidAt: invalidAt
        )
        let rendered = TwoChannelConfirm.renderTerminalPair(for: result, timeZone: "CET")
        let expected = "rotated OVH_APP_KEY (old …a3f2 invalid since 16:55:23 CET)"
        #expect(rendered == expected)
    }

    @Test("fan-out — both channels (mattermost + ntfy) recorded with identical message + undo link")
    func test_cli_rotateSuccess_fanoutPostsBothChannels_withUndoLink() async throws {
        let mm = RecordingConfirmationChannel(name: "mattermost")
        let ntfy = RecordingConfirmationChannel(name: "ntfy")
        let result = RotationResult(
            secretName: "BREVO_SMTP",
            oldJtiSuffix: "9001",
            invalidAt: Date(timeIntervalSince1970: 0)
        )
        let (message, undo) = try await TwoChannelConfirm.fanout(
            result: result,
            channels: [mm, ntfy],
            undoTTL: 300
        )
        let mmPosted = await mm.snapshot()
        let ntfyPosted = await ntfy.snapshot()
        #expect(mmPosted.count == 1)
        #expect(ntfyPosted.count == 1)
        #expect(mmPosted.first?.message == message)
        #expect(mmPosted.first?.undoLink == undo)
        #expect(ntfyPosted.first?.message == message)
        #expect(ntfyPosted.first?.undoLink == undo)
        #expect(undo == "/undo/BREVO_SMTP?ttl=300")
        #expect(message.contains("reborn"))
    }
}
