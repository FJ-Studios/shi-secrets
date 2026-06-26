import Foundation
import ShiSecretsKit

// BrokerdHelpers — shared pure utilities used by both RequestGateway and BrokerDaemon.
//
// Wave A4 panel finding (sensei MED-1, tech-expert MED-2): `deriveSecretName` and
// `logAuditFailClosed` were copy-pasted verbatim into both actors after the
// RequestGateway extraction. Centralising them here prevents drift when the
// AuditRow schema or logging surface changes.
//
// Both functions are pure / nonisolated — no actor state involved.

/// Derives the audit-row secret name from a raw scope string.
/// Truncates to `AuditWriter.maxSecretNameLength` (64) and falls back to
/// "unknown" for empty scopes (e.g., unminted deny rows with empty scope).
func brokerdDeriveSecretName(from scope: String) -> String {
    let trimmed = String(scope.prefix(AuditWriter.maxSecretNameLength))
    return trimmed.isEmpty ? "unknown" : trimmed
}

/// Writes an audit-fail-closed diagnostic to stderr.
/// Used when `audit.append` throws — the caller must still deny the request;
/// this call is purely for ops observability.
///
/// Message format:
///   shikki-brokerd: audit write failed, failing closed — <context>: <error>
///   Check disk space and permissions on ~/.shikki/audit/. Run `shi secrets doctor`.
func brokerdLogAuditFailClosed(error: Swift.Error, context: String) {
    let message = """
        shikki-brokerd: audit write failed, failing closed — \(context): \(error)
        Check disk space and permissions on ~/.shikki/audit/. Run `shi secrets doctor` to validate the audit path.

        """
    if let data = message.data(using: .utf8) {
        try? FileHandle.standardError.write(contentsOf: data)
    }
}
