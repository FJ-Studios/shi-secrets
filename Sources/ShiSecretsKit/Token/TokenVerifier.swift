import Crypto
import Foundation

// TokenVerifier — gate that runs on every incoming ShikkiSBT presentation.
//
// Order of checks (BR-A-08, BR-A-09, BR-A-10, BR-A-12):
//   1. signature under pinned broker pubkey → bad_signature if fail
//   2. nbf ≤ now                            → token_not_yet_valid
//   3. now ≤ dies_at                        → token_expired
//   4. registry.isRevoked(jti)               → token_revoked
//
// On every failure the verifier appends EXACTLY ONE audit row before
// returning the DenyReason (BR-G-01 — audit before plaintext). On
// success the verifier returns `nil` and the caller proceeds to
// fulfil the request; the caller is responsible for the `allow` row.

public actor TokenVerifier {

    private let registry: TokenRegistry
    private let audit: AuditWriter
    private let publicKey: Curve25519.Signing.PublicKey
    /// Review finding U8 — monotonic clock floor. Updated on every
    /// successful verify call to the max of the caller-supplied `now`
    /// and the current floor. Any subsequent call whose `now` is less
    /// than this floor is rejected with `.tokenClockRollback`.
    private var lastObservedNow: Date = .distantPast

    public init(
        registry: TokenRegistry,
        audit: AuditWriter,
        publicKey: Curve25519.Signing.PublicKey
    ) {
        self.registry = registry
        self.audit = audit
        self.publicKey = publicKey
    }

    /// Verifies a presented token. Returns `nil` on success; on failure
    /// returns the DenyReason and appends exactly one audit row.
    public func verify(
        token: TokenMinter.Token,
        at now: Date,
        callerUid: Int32?,
        transport: AuditRow.Transport,
        secretName: String
    ) async -> AuditRow.DenyReason? {
        // Review finding U8 — reject a caller-supplied `now` that moved
        // backwards vs the verifier's monotonic floor. Defends against
        // NTP rollbacks / wall-clock tampering games.
        if now < lastObservedNow {
            await appendDeny(
                token: token, reason: .tokenClockRollback, now: now,
                callerUid: callerUid, transport: transport, secretName: secretName
            )
            return .tokenClockRollback
        }
        // Advance the floor before any check — even denies count, so a
        // replay-after-rollback cannot game us.
        lastObservedNow = now

        // Review finding U4 — capture the revoke epoch at entry.
        let entryEpoch = await registry.revokeEpoch
        // 1. Signature check.
        let canonical: Data
        do {
            canonical = try TokenMinter.canonicalize(token.claims)
        } catch {
            await appendDeny(
                token: token, reason: .badSignature, now: now,
                callerUid: callerUid, transport: transport, secretName: secretName
            )
            return .badSignature
        }
        if !publicKey.isValidSignature(token.envelope, for: canonical) {
            await appendDeny(
                token: token, reason: .badSignature, now: now,
                callerUid: callerUid, transport: transport, secretName: secretName
            )
            return .badSignature
        }

        // 2. Not-yet-valid.
        if now < token.claims.nbf {
            await appendDeny(
                token: token, reason: .tokenNotYetValid, now: now,
                callerUid: callerUid, transport: transport, secretName: secretName
            )
            return .tokenNotYetValid
        }

        // 3. Expired.
        if now > token.claims.diesAt {
            await appendDeny(
                token: token, reason: .tokenExpired, now: now,
                callerUid: callerUid, transport: transport, secretName: secretName
            )
            return .tokenExpired
        }

        // 4. Revoked.
        if await registry.isRevoked(jti: token.claims.jti) {
            await appendDeny(
                token: token, reason: .tokenRevoked, now: now,
                callerUid: callerUid, transport: transport, secretName: secretName
            )
            return .tokenRevoked
        }

        // Review finding U4 — re-check the revoke epoch at exit. If a
        // concurrent `revokeAllBots` ran in-window AND this jti is now
        // revoked, treat the call as if we'd observed the revoke on the
        // first read.
        let exitEpoch = await registry.revokeEpoch
        if exitEpoch != entryEpoch {
            let nowRevoked = await registry.isRevoked(jti: token.claims.jti)
            if nowRevoked {
                await appendDeny(
                    token: token, reason: .tokenRevoked, now: now,
                    callerUid: callerUid, transport: transport, secretName: secretName
                )
                return .tokenRevoked
            }
        }

        return nil
    }

    private func appendDeny(
        token: TokenMinter.Token,
        reason: AuditRow.DenyReason,
        now: Date,
        callerUid: Int32?,
        transport: AuditRow.Transport,
        secretName: String
    ) async {
        let row = AuditRow(
            ts: now,
            tokenJti: token.claims.jti,
            callerUid: callerUid,
            callerTransport: transport,
            secretName: secretName,
            op: token.claims.op,
            allow: .deny,
            reason: reason,
            llmTouched: token.claims.llmTouched
        )
        do {
            try await audit.append(row)
        } catch {
            // Auditing a deny row must never be lossy. In Wave 2 the
            // in-memory writer cannot fail on a well-formed row; once a
            // real backend lands, surface via AppLog. Review finding #17
            // — linked to the deviation log entry so the follow-up
            // points to tracked work rather than a bare wave marker.
            // TODO(v1.1 follow-up, tracked in features/shikki-secrets-broker.md Implementation Log §W2-dev-4)
            // Fail-closed path on the request surface lives in
            // BrokerDaemon.handleRequest — see `DenyReason.auditWriteFailed`.
            _ = error
        }
    }
}
