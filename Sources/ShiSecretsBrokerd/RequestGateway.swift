import Foundation
import ShiSecretsKit

// RequestGateway — validates an incoming BrokerRequest before the mint path.
//
// Extracted from BrokerDaemon.handleRequest (Wave A4, @sensei panel finding).
// Owns: ScopeValidator, ScopePolicy blast-radius check, BWClient session check.
// Returns AuthoriseOutcome.allow (with captured preMintSessionEpoch) or
// AuthoriseOutcome.deny (with audit row already written + deny reason).
//
// BrokerDaemon.handleRequest delegates ALL pre-mint checks here, so the
// daemon's handleRequest body starts at the mint step.

public actor RequestGateway {

    private let scopeValidator: ScopeValidator
    private let systemScopePolicy: ScopePolicy?
    private let bwClient: any BWClient
    private let audit: AuditWriter

    public init(
        scopeValidator: ScopeValidator,
        systemScopePolicy: ScopePolicy? = nil,
        bwClient: any BWClient,
        audit: AuditWriter
    ) {
        self.scopeValidator = scopeValidator
        self.systemScopePolicy = systemScopePolicy
        self.bwClient = bwClient
        self.audit = audit
    }

    // MARK: - AuthoriseOutcome

    public enum AuthoriseOutcome: Sendable {
        case allow(preMintSessionEpoch: UInt64)
        case deny(reason: AuditRow.DenyReason)
    }

    // MARK: - authorise

    /// Validates a BrokerRequest before the mint path. Returns `.allow` with
    /// the pre-mint session epoch (for post-mint U5 race-closure) or `.deny`
    /// with the audit row already written.
    public func authorise(
        _ request: BrokerRequest,
        wrapped: WrappedRequest,
        now: Date
    ) async -> AuthoriseOutcome {
        // Scope-validate the caller's pattern (BR-H-04, -H-06, finding #8).
        do {
            try scopeValidator.validate(pattern: request.scope)
        } catch ScopeValidator.ValidationError.scopeTooLong {
            await writeDenyOrFailClosed(
                jti: "unminted", request: request, wrapped: wrapped,
                now: now, reason: .scopeTooLong
            )
            return .deny(reason: .scopeTooLong)
        } catch ScopeValidator.ValidationError.scopePatternDenied {
            await writeDenyOrFailClosed(
                jti: "unminted", request: request, wrapped: wrapped,
                now: now, reason: .scopePatternDenied
            )
            return .deny(reason: .scopePatternDenied)
        } catch ScopeValidator.ValidationError.regexSyntaxForbidden {
            await writeDenyOrFailClosed(
                jti: "unminted", request: request, wrapped: wrapped,
                now: now, reason: .scopePatternDenied
            )
            return .deny(reason: .scopePatternDenied)
        } catch {
            await writeDenyOrFailClosed(
                jti: "unminted", request: request, wrapped: wrapped,
                now: now, reason: .scopeDenied
            )
            return .deny(reason: .scopeDenied)
        }

        // W6.5c CRIT-1 fix: secondary blast-radius enforcement via
        // per-system ScopePolicy. The toml allowlist (ScopeValidator above)
        // can be operator-misconfigured; this check is the architectural
        // guarantee that a compromised brokerd cannot read another system's
        // collection even if the allowlist accidentally permits it.
        //
        // v0.5.0 / Wave A3: uses dedicated .scopeBlastRadiusDenied so audit
        // ops can distinguish a toml-config gate (.scopePatternDenied above)
        // from a real W6.5c F-PSA-3 isolation refusal.
        if let policy = systemScopePolicy, !policy.canRead(path: request.scope) {
            await writeDenyOrFailClosed(
                jti: "unminted", request: request, wrapped: wrapped,
                now: now, reason: .scopeBlastRadiusDenied
            )
            return .deny(reason: .scopeBlastRadiusDenied)
        }

        // BWClient session must still be valid — BR-F-07. Review finding #3:
        // the bw-session-invalid path was previously overloaded onto
        // `.incidentBypass`; surface it as its own dedicated reason so
        // audit/TUI can distinguish operator-initiated bw revoke from a
        // generic incident bypass.
        // Review finding U5 — capture the bw-session epoch now and
        // re-check after mint so a concurrent invalidateSession cannot
        // slip through while we're signing.
        let preMintSessionEpoch = await bwClient.sessionEpoch
        guard await bwClient.isSessionValid else {
            await writeDenyOrFailClosed(
                jti: "unminted", request: request, wrapped: wrapped,
                now: now, reason: .brokerSessionInvalid
            )
            return .deny(reason: .brokerSessionInvalid)
        }

        return .allow(preMintSessionEpoch: preMintSessionEpoch)
    }

    // MARK: - Audit helpers

    /// Writes a deny audit row. On append failure the deny is still returned
    /// (fail-closed: the caller MUST deny regardless of audit result).
    private func writeDenyOrFailClosed(
        jti: String,
        request: BrokerRequest,
        wrapped: WrappedRequest,
        now: Date,
        reason: AuditRow.DenyReason
    ) async {
        let row = AuditRow(
            ts: now,
            tokenJti: jti,
            callerUid: wrapped.peerUid.map { Int32(bitPattern: $0) },
            callerTransport: wrapped.transport,
            secretName: deriveSecretName(from: request.scope),
            op: request.op,
            allow: .deny,
            reason: reason,
            llmTouched: wrapped.llmTouched
        )
        do {
            try await audit.append(row)
        } catch {
            Self.logAuditFailClosed(error: error, context: "deny row (\(reason.rawValue))")
        }
    }

    private nonisolated func deriveSecretName(from scope: String) -> String {
        let trimmed = String(scope.prefix(AuditWriter.maxSecretNameLength))
        return trimmed.isEmpty ? "unknown" : trimmed
    }

    private static func logAuditFailClosed(error: Swift.Error, context: String) {
        let message = "shikki-brokerd: audit write failed, failing closed — \(context): \(error)\n"
        if let data = message.data(using: .utf8) {
            try? FileHandle.standardError.write(contentsOf: data)
        }
    }
}
