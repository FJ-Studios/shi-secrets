import Foundation
import ShiSecretsKit

// SeamsLedgerView — `shi audit secrets seams` Golden Seam Ledger view
// (T63 — BR-G-03).
//
// A scrollable, chronological render over `seams` table rows. Display-
// only: read-only, never mutates. Rows carry signal / ts / secret_name /
// outcome columns.

public enum SeamsLedgerView {

    public static let header = "ts                   secret            signal                            outcome"

    public static func render(_ rows: [SeamsWriter.Row]) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.timeZone = TimeZone(identifier: "UTC")
        var lines: [String] = []
        lines.append("── Golden Seam Ledger ──")
        lines.append(header)
        for row in rows.sorted(by: { $0.ts < $1.ts }) {
            let ts = formatter.string(from: row.ts)
            let signal = displayName(for: row.signal)
            let outcome = row.outcome.rawValue
            lines.append("\(ts)  \(pad(row.secretName, 16))  \(pad(signal, 32))  \(outcome)")
        }
        if rows.isEmpty {
            lines.append("(ledger empty — no seams written)")
        }
        return lines.joined(separator: "\n")
    }

    private static func pad(_ s: String, _ w: Int) -> String {
        if s.count >= w { return String(s.prefix(w)) }
        return s + String(repeating: " ", count: w - s.count)
    }

    private static func displayName(for sig: AnomalySignal) -> String {
        switch sig {
        case .hibp(let id):                          return "hibp(\(id))"
        case .unexpectedIP:                          return "unexpected_ip"
        case .failedFetchBurst:                      return "failed_fetch_burst"
        case .vendorBreach(let v, _):                return "vendor_breach(\(v))"
        case .selfRevokeMissed:                      return "self_revoke_missed"
        case .manifestSigFailed(let v):              return "manifest_sig_failed(\(v))"
        case .noDriverRegistered(let vendor, _):     return "no_driver_registered(\(vendor))"
        case .llmQueueSaturated(let sid, _):         return "llm_queue_saturated(\(sid))"
        case .persistCompensationNoOp(let scope):    return "persist_compensation_noop(\(scope))"
        case .persistCompensationFailed(let s, _):   return "persist_compensation_failed(\(s))"
        case .rotationHandlerDoubleFailure(let n, _, _):
            return "rotation_handler_double_failure(\(n))"
        case .adminActionExecuted(let action, _, _):
            return "admin_action_executed(\(action))"
        }
    }
}
