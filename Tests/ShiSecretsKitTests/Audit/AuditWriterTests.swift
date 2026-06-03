import Foundation
import Testing
@testable import ShiSecretsKit

// AuditWriter tests (Task 22 — BR-G-01, BR-G-02, BR-G-04, BR-J-05).
//
// The writer is append-only: every token-validated fetch (allow) AND every
// denied request (deny) must persist exactly one row before plaintext is
// returned to the caller (BR-G-01). No plaintext, no ciphertext, no token
// bytes may appear in any column (BR-G-02 + BR-J-05).
//
// Wave 2 backs the writer with an in-memory store that mirrors the 0031 SQL
// schema exactly; Wave 4 swaps the backend for a real ShikkiDB driver.

@Suite("AuditWriter")
struct AuditWriterTests {

    private func sampleRow(
        allow: AuditRow.Allow = .allow,
        reason: AuditRow.DenyReason? = nil,
        secretName: String = "ovh:dns"
    ) -> AuditRow {
        AuditRow(
            ts: Date(timeIntervalSince1970: 1_700_000_000),
            tokenJti: "01JABCDEFGHIJKLMNOPQRSTUVW",
            callerUid: 1001,
            callerTransport: .unix,
            secretName: secretName,
            op: .read,
            allow: allow,
            reason: reason,
            llmTouched: false
        )
    }

    @Test("every token-validated fetch appends exactly one row before plaintext returned")
    func audit_everyTokenValidatedFetch_appendsExactlyOneRow_beforePlaintextReturned() async throws {
        let writer = AuditWriter()
        let row = sampleRow()
        try await writer.append(row)

        let rows = await writer.all()
        #expect(rows.count == 1)
        #expect(rows.first?.allow == .allow)
    }

    @Test("rows never contain plaintext, ciphertext, or token bytes")
    func audit_rowsNeverContainPlaintext_norCiphertext_norTokenBytes() async throws {
        let writer = AuditWriter()
        // BR-J-05 — secret_name is a reference only. The writer body-scanner
        // rejects rows whose secret_name length > 64 (likely a payload smuggle).
        let oversizedName = String(repeating: "x", count: 65)
        let bad = sampleRow(secretName: oversizedName)
        await #expect(throws: AuditWriter.AppendError.self) {
            try await writer.append(bad)
        }
        let rows = await writer.all()
        #expect(rows.isEmpty)
    }

    @Test(
        "denied request appends row with allow=deny + machine-readable reason",
        arguments: [
            AuditRow.DenyReason.tokenExpired,
            .tokenNotYetValid,
            .tokenRevoked,
            .badSignature,
            .replay,
            .scopeDenied,
            .scopePatternDenied,
            .scopeTooLong,
            .opMismatch,
            .rotationFailed,
            .manifestSigFailed,
            .incidentBypass,
            .brokerSessionInvalid,
            .auditWriteFailed,
        ]
    )
    func audit_deniedRequest_appendsRowWithAllowDeny_machineReadableReasonCode(
        reason: AuditRow.DenyReason
    ) async throws {
        let writer = AuditWriter()
        let row = sampleRow(allow: .deny, reason: reason)
        try await writer.append(row)
        let stored = await writer.all()
        #expect(stored.count == 1)
        #expect(stored.first?.allow == .deny)
        #expect(stored.first?.reason == reason)
    }

    @Test("in-memory cap enforces FIFO eviction — oldest 50 rotate out at 10_050 appends (T3)")
    func test_auditWriter_inMemoryCap_enforcesFIFOEviction() async throws {
        // 3rd-pass validator T3 — U12 declared a sliding-window cap at
        // AuditWriter.maxInMemoryRows=10_000 but the test suite never
        // walked past the ceiling. Append 10_050 rows with distinct
        // jtis; expect count=10_000, oldest 50 (jtis 0..49) evicted,
        // oldest survivor is the 51st appended (jti_0050).
        let writer = AuditWriter()
        let baseTs = Date(timeIntervalSince1970: 1_700_000_000)
        for i in 0 ..< 10_050 {
            // 26-char ULID-shape-ish — we only care the writer accepts it.
            let jti = String(format: "01JABCDEFGHIJKLMNOPQR%05d", i).prefix(26)
            let row = AuditRow(
                ts: baseTs.addingTimeInterval(Double(i)),
                tokenJti: String(jti),
                callerUid: 1001,
                callerTransport: .unix,
                secretName: "ovh:dns",
                op: .read,
                allow: .allow,
                reason: nil,
                llmTouched: false
            )
            try await writer.append(row)
        }
        let count = await writer.count()
        #expect(count == 10_000)
        let rows = await writer.all()
        #expect(rows.count == 10_000)
        // The oldest surviving row is the 51st appended (index 50).
        let firstSurvivor = try #require(rows.first)
        let expectedFirstJti = String(String(format: "01JABCDEFGHIJKLMNOPQR%05d", 50).prefix(26))
        #expect(firstSurvivor.tokenJti == expectedFirstJti)
        // The newest row is the 10_049th appended.
        let lastSurvivor = try #require(rows.last)
        let expectedLastJti = String(String(format: "01JABCDEFGHIJKLMNOPQR%05d", 10_049).prefix(26))
        #expect(lastSurvivor.tokenJti == expectedLastJti)
    }
}
