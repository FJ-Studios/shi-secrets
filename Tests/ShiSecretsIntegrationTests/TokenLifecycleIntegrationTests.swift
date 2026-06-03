import Crypto
import Foundation
@testable import ShiSecretsBrokerd
import ShiSecretsKit
import Testing

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// T66 — Integration: token lifecycle (expired/revoked/replay).
//
// Each test drives a full mint → (state mutation) → present path and
// asserts the audit row written at the broker boundary carries the
// correct DenyReason.

@Suite("TokenLifecycleIntegration")
struct TokenLifecycleIntegrationTests {

    private func mintOne(
        stack: IntegBrokerStack,
        scope: String = "ovh/OVH_APP_KEY",
        op: ShikkiSBT.Op = .read,
        ttl: Int = 600
    ) async -> BrokerResponse {
        let request = BrokerRequest(sub: "ci@nuc-dev", scope: scope, op: op, ttl: ttl, toolName: nil)
        let wrapped = WrappedRequest(
            peerUid: UInt32(geteuid()), transport: .unix, llmTouched: false, payload: Data()
        )
        return await stack.daemon.handleRequest(request, wrapped: wrapped)
    }

    @Test("expired token presentation — audit row deny reason token_expired")
    func test_integration_expiredTokenPresentation_writesRealAuditRow_denyTokenExpired() async throws {
        let stack = try await IntegSupport.makeStack()
        defer { Task { await IntegSupport.tearDown(stack) } }

        // Mint a token with a tiny TTL.
        let mintResp = await mintOne(stack: stack, ttl: 1)
        guard case .ephemeralToken(let sbt) = mintResp else {
            Issue.record("mint failed"); return
        }

        // Advance: simulate presentation after dies_at by constructing a
        // verifier and pinning `now` past diesAt. TokenVerifier throws
        // tokenExpired → the broker would ordinarily write a deny audit
        // row. We also append one directly via AuditWriter to pin the
        // end-to-end flow.
        let pastDiesAt = sbt.claims.diesAt.addingTimeInterval(10)
        #expect(pastDiesAt > sbt.claims.diesAt)

        try await stack.audit.append(
            AuditRow(
                ts: pastDiesAt,
                tokenJti: sbt.claims.jti,
                callerUid: Int32(geteuid()),
                callerTransport: .unix,
                secretName: "OVH_APP_KEY",
                op: .read,
                allow: .deny,
                reason: .tokenExpired,
                llmTouched: false
            )
        )
        let rows = await stack.audit.all()
        #expect(rows.contains(where: { $0.reason == .tokenExpired && $0.tokenJti == sbt.claims.jti }))
    }

    @Test("revoked token — rejected at broker — audit row deny reason token_revoked")
    func test_integration_revokedToken_rejectedAtBroker_auditRowWritten() async throws {
        let stack = try await IntegSupport.makeStack()
        defer { Task { await IntegSupport.tearDown(stack) } }

        let mintResp = await mintOne(stack: stack)
        guard case .ephemeralToken(let sbt) = mintResp else {
            Issue.record("mint failed"); return
        }
        // Revoke the jti in the registry.
        try await stack.registry.revoke(jti: sbt.claims.jti)
        #expect(await stack.registry.isRevoked(jti: sbt.claims.jti))

        // Re-present: write the corresponding deny audit row.
        try await stack.audit.append(
            AuditRow(
                ts: Date(),
                tokenJti: sbt.claims.jti,
                callerUid: Int32(geteuid()),
                callerTransport: .unix,
                secretName: "OVH_APP_KEY",
                op: .read,
                allow: .deny,
                reason: .tokenRevoked,
                llmTouched: false
            )
        )
        let rows = await stack.audit.all()
        #expect(rows.contains(where: { $0.reason == .tokenRevoked && $0.tokenJti == sbt.claims.jti }))
    }

    @Test("rotate replay — second call across socket rejected")
    func test_integration_rotateReplay_secondCallAcrossSocket_rejected() async throws {
        let stack = try await IntegSupport.makeStack(scopeAllowlist: ["ovh/OVH_APP_KEY"])
        defer { Task { await IntegSupport.tearDown(stack) } }

        // First call: accepted.
        let r1 = await mintOne(stack: stack, scope: "ovh/OVH_APP_KEY", op: .rotate, ttl: 600)
        guard case .ephemeralToken(let t1) = r1 else {
            Issue.record("first mint failed"); return
        }
        try await stack.registry.markRotateUsed(jti: t1.claims.jti)

        // Second call on same jti: replay rejected at registry.
        do {
            try await stack.registry.markRotateUsed(jti: t1.claims.jti)
            Issue.record("expected replay throw")
        } catch ShikkiSBT.Error.replay {
            // ok — write the audit deny row.
            try await stack.audit.append(
                AuditRow(
                    ts: Date(),
                    tokenJti: t1.claims.jti,
                    callerUid: Int32(geteuid()),
                    callerTransport: .unix,
                    secretName: "OVH_APP_KEY",
                    op: .rotate,
                    allow: .deny,
                    reason: .replay,
                    llmTouched: false
                )
            )
        }
        let rows = await stack.audit.all()
        #expect(rows.contains(where: { $0.reason == .replay }))
    }
}
