import Foundation
import Testing
@testable import ShiSecretsKit

// RefreshPolicyTests — per-kind default invariants + Codable round-trip
// for the Phase 0.3a (BR-G-09) refresh-before-dies policy types.

@Suite("RefreshPolicy")
struct RefreshPolicyTests {

    @Test("RefreshPolicy round-trips through JSON")
    func test_refreshPolicy_codableRoundTrip() throws {
        let original = RefreshPolicy(ttlSeconds: 3_600, refreshBeforeSeconds: 1_800, revocationSLAMSeconds: 500)
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(RefreshPolicy.self, from: data)
        #expect(decoded == original)
    }

    @Test("Interactive default = short TTL, no preemptive refresh")
    func test_defaults_interactive() {
        let p = RefreshPolicy.defaultPolicy(for: .interactive)
        #expect(p.ttlSeconds == 300)
        #expect(p.refreshBeforeSeconds == 0)
    }

    @Test("Daemon default = 1h TTL, refresh at half-life")
    func test_defaults_daemon() {
        let p = RefreshPolicy.defaultPolicy(for: .daemon)
        #expect(p.ttlSeconds == 3_600)
        #expect(p.refreshBeforeSeconds == 1_800)
        #expect(p.revocationSLAMSeconds <= 1_000)
    }

    @Test("MCP server TTL never exceeds 600s (BR-A-03)")
    func test_defaults_mcp_respectsBRA03() {
        let p = RefreshPolicy.defaultPolicy(for: .mcpServer)
        // BR-A-03: MCP TTL hard-capped at 600s.
        #expect(p.ttlSeconds <= 600)
        #expect(p.refreshBeforeSeconds > 0)
        // Tightest revocation SLA — LLM-touched is compromised-on-leak.
        #expect(p.revocationSLAMSeconds < RefreshPolicy.defaultPolicy(for: .daemon).revocationSLAMSeconds)
    }

    @Test("Long-lived default = multi-hour TTL with refresh-before-dies window")
    func test_defaults_longLived() {
        let p = RefreshPolicy.defaultPolicy(for: .longLived)
        #expect(p.ttlSeconds == 14_400)
        // refreshBefore must be strictly less than TTL so we refresh BEFORE dying.
        #expect(p.refreshBeforeSeconds < p.ttlSeconds)
        #expect(p.refreshBeforeSeconds > 0)
    }

    @Test("All ConsumerKind cases have a default policy (no missing branch)")
    func test_defaults_coverEveryConsumerKind() {
        for kind in ConsumerKind.allCases {
            let p = RefreshPolicy.defaultPolicy(for: kind)
            #expect(p.ttlSeconds > 0, "\(kind) must have positive TTL")
            #expect(p.refreshBeforeSeconds >= 0, "\(kind) refresh-before must be non-negative")
            #expect(p.refreshBeforeSeconds < p.ttlSeconds, "\(kind) must refresh BEFORE dying")
        }
    }

    @Test("ConsumerKind round-trips through JSON")
    func test_consumerKind_codableRoundTrip() throws {
        for kind in ConsumerKind.allCases {
            let data = try JSONEncoder().encode(kind)
            let decoded = try JSONDecoder().decode(ConsumerKind.self, from: data)
            #expect(decoded == kind)
        }
    }
}
