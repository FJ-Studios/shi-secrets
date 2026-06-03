import Foundation
import Testing
@testable import ShiSecretsKit

// AuditRow + Transport + Allow + DenyReason shape tests (Task 12 — BR-G-04,
// BR-J-01). Wave 1 asserts the type's shape only; writer behavior arrives
// in Wave 2 (Task 22). Every DenyReason case must round-trip — the set is
// the full machine-readable reason vocabulary for `allow=deny` rows.

@Suite("AuditRow")
struct AuditRowTests {

    @Test(
        "denied request row carries allow=deny plus a machine-readable reason code",
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
    func deniedRequest_appendsRowWithAllowDeny_machineReadableReasonCode(
        reason: AuditRow.DenyReason
    ) throws {
        let row = AuditRow(
            ts: Date(timeIntervalSince1970: 1_700_000_000),
            tokenJti: "01JABCDEFGHIJKLMNOPQRSTUVW",
            callerUid: 1001,
            callerTransport: .unix,
            secretName: "ovh:dns",
            op: .read,
            allow: .deny,
            reason: reason,
            llmTouched: false
        )

        #expect(row.allow == .deny)
        #expect(row.reason == reason)
        #expect(row.callerTransport == .unix)
        #expect(row.op == .read)

        // Every reason must have a stable machine-readable raw value with no
        // spaces / uppercase — it ends up in the `reason` column verbatim.
        #expect(!reason.rawValue.isEmpty)
        #expect(reason.rawValue == reason.rawValue.lowercased())
        #expect(!reason.rawValue.contains(" "))

        // Round-trip through Codable preserves all fields.
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let data = try encoder.encode(row)
        let decoded = try decoder.decode(AuditRow.self, from: data)
        #expect(decoded == row)
    }
}
