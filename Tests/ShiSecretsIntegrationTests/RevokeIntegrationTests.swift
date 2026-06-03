import Foundation
@testable import ShiSecretsBrokerd
@testable import ShiSecretsKit
import Testing

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// T68 — Integration: revokeAllBots atomicity + bw session revoke window.

@Suite("RevokeIntegration")
struct RevokeIntegrationTests {

    @Test("revokeAllBots — atomic transaction against real registry — passkey rows preserved")
    func test_integration_revokeAllBots_atomic_againstRealShikkiDb() async throws {
        let stack = try await IntegSupport.makeStack()
        defer { Task { await IntegSupport.tearDown(stack) } }

        let baseNbf = Date()
        let diesAt = baseNbf.addingTimeInterval(600)
        // Seed the registry: 3 bot rows + 2 passkey rows.
        for (idx, isPasskey) in [(0, false), (1, false), (2, false), (3, true), (4, true)] {
            let jtiLen = 26
            var jti = "01JC"
            jti += String(repeating: "0", count: max(0, jtiLen - jti.count - 2))
            // produce 2-char suffix deterministic
            let suffix = String(format: "A%x", idx)
            jti = String((jti + suffix).prefix(jtiLen))
            let row = TokenRegistry.Row(
                jti: jti,
                sub: isPasskey ? "user@passkey" : "bot-\(idx)@nuc-dev",
                scope: "ovh/*",
                op: .read,
                nbf: baseNbf,
                diesAt: diesAt,
                llmTouched: false,
                passkeyPath: isPasskey
            )
            try await stack.registry.insert(row)
        }
        let count = try await stack.registry.revokeAllBots()
        #expect(count == 3)
        // All 3 bot rows revoked, 2 passkey rows untouched.
        let all = await stack.registry.all()
        let revokedCount = all.filter { $0.revoked }.count
        let untouchedPasskey = all.filter { $0.passkeyPath && !$0.revoked }.count
        #expect(revokedCount == 3)
        #expect(untouchedPasskey == 2)
    }

    @Test("broker bw-session revoked — new issuance blocked within 5s, existing rows retained")
    func test_integration_brokerBwSessionRevoked_newIssuanceBlockedWithin5s_existingTokensStillUsable() async throws {
        let stack = try await IntegSupport.makeStack()
        defer { Task { await IntegSupport.tearDown(stack) } }
        try await stack.daemon.start()

        // Mint one to establish a baseline.
        let pre = await stack.daemon.handleRequest(
            BrokerRequest(sub: "ci", scope: "ovh/OVH_APP_KEY", op: .read, ttl: 300, toolName: nil),
            wrapped: WrappedRequest(peerUid: UInt32(geteuid()), transport: .unix, llmTouched: false, payload: Data())
        )
        guard case .ephemeralToken(let preToken) = pre else {
            Issue.record("pre-mint failed"); return
        }

        let start = Date()
        await stack.daemon.revokeBWSession()
        #expect(Date().timeIntervalSince(start) < 5.0)

        // New mint is denied. Review finding #3 — bw-session-invalid now
        // surfaces as its own dedicated reason code rather than the
        // overloaded `.incidentBypass`.
        let post = await stack.daemon.handleRequest(
            BrokerRequest(sub: "ci", scope: "ovh/OVH_APP_KEY", op: .read, ttl: 300, toolName: nil),
            wrapped: WrappedRequest(peerUid: UInt32(geteuid()), transport: .unix, llmTouched: false, payload: Data())
        )
        if case .deny(let reason) = post {
            #expect(reason == .brokerSessionInvalid)
        } else {
            Issue.record("expected deny after revoke, got \(post)")
        }

        // Existing row for the pre-revoke token still present (never deleted).
        let row = await stack.registry.row(jti: preToken.claims.jti)
        #expect(row != nil)
        #expect(row?.revoked == false)  // not globally revoked by bw session invalidation
    }
}
