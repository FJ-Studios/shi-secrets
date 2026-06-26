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
//
// INVARIANT: RequestGateway.bwClient and BrokerDaemon.bwClient MUST be the
// same actor reference. The U5 post-mint epoch race-closure (BrokerDaemon
// line ~393) re-reads bwClient.sessionEpoch and compares it against the
// preMintSessionEpoch captured here; divergent references would break that check.

public actor RequestGateway {

    private let scopeValidator: ScopeValidator
    private let systemScopePolicy: ScopePolicy?
    private let bwClient: any BWClient
    private let audit: AuditWriter

    /// Creates a RequestGateway.
    ///
    /// - Precondition: `scopeValidator.allowlist` must be non-empty.
    ///   An empty allowlist means no scope can ever pass, which is a
    ///   misconfiguration (the `Main.swift` entry point enforces this via
    ///   `exit(78)` before constructing the gateway; callers that bypass
    ///   Main.swift — e.g. tests — should pass a non-empty allowlist or
    ///   the wildcard `["**"]` explicitly).
    public init(
        scopeValidator: ScopeValidator,
        systemScopePolicy: ScopePolicy? = nil,
        bwClient: any BWClient,
        audit: AuditWriter
    ) {
        // @ronin MED-6 guard: catch the misconfiguration at construction time
        // rather than silently denying every request. Mirrors the exit(78) in
        // Main.swift so the invariant is enforced even when Main is bypassed.
        precondition(
            !scopeValidator.allowlist.isEmpty,
            "RequestGateway: scopeValidator.allowlist must not be empty — every request would be denied. Pass [\"**\"] for dev/test or configure ~/.shikki/settings/secrets-brokerd.toml."
        )
        self.scopeValidator = scopeValidator
        self.systemScopePolicy = systemScopePolicy
        self.bwClient = bwClient
        self.audit = audit
    }

    // MARK: - AuthoriseOutcome

    /// Outcome of a pre-mint authorisation check.
    ///
    /// `internal` visibility is sufficient: only `BrokerDaemon.handleRequest`
    /// consumes this type within the same module. Tests access it via
    /// `@testable import ShiSecretsBrokerd`. Making it `public` would widen
    /// the API surface and make future renames breaking changes.
    enum AuthoriseOutcome: Sendable {
        case allow(preMintSessionEpoch: UInt64)
        case deny(reason: AuditRow.DenyReason)
    }

    // MARK: - authorise

    /// Validates a BrokerRequest before the mint path. Returns `.allow` with
    /// the pre-mint session epoch (for post-mint U5 race-closure) or `.deny`
    /// with the audit row already written.
    ///
    /// On `.deny`, the audit row has already been persisted (or a fail-closed
    /// log emitted if the audit write itself threw). The caller does not need
    /// to write another deny row for the same pre-mint rejection.
    ///
    /// Note: `writeDenyOrFailClosed` (below) returns `void` — unlike the
    /// `BrokerDaemon.writeDenyOrFailClosed` which returns `BrokerResponse?`.
    /// The asymmetry is intentional: here the return of `.deny(reason)` is
    /// always done by the caller unconditionally; the daemon version needs the
    /// nil/BrokerResponse sentinel to control which deny case to return at call
    /// site. The two variants serve different structural needs.
    func authorise(
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
            // Note: regexSyntaxForbidden is intentionally aliased to
            // .scopePatternDenied in audit rows. There is no dedicated
            // AuditRow.DenyReason for regex-injection probes yet; a future
            // wave can add `.scopeRegexInjectionBlocked` for triage distinction.
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
        //
        // Review finding U5 — capture the bw-session epoch now (two separate
        // await calls: sessionEpoch then isSessionValid). Between these two
        // calls, `invalidateSession()` could fire: if `isSessionValid` still
        // returns true in that window, the .allow carries the old epoch and the
        // post-mint U5 check (BrokerDaemon.handleRequest line ~393) will catch
        // the mismatch and revoke. This is defense-in-depth, not a bypass.
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

    /// Writes a deny audit row. On append failure logs to stderr and continues
    /// (fail-closed: the caller MUST return `.deny` regardless of audit result).
    ///
    /// Return type is `void` — unlike `BrokerDaemon.writeDenyOrFailClosed` which
    /// returns `BrokerResponse?`. See the `authorise` doc comment for the rationale.
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
            secretName: brokerdDeriveSecretName(from: request.scope),
            op: request.op,
            allow: .deny,
            reason: reason,
            llmTouched: wrapped.llmTouched
        )
        do {
            try await audit.append(row)
        } catch {
            brokerdLogAuditFailClosed(error: error, context: "deny row (\(reason.rawValue))")
        }
    }
}
