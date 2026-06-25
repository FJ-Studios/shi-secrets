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

// SecretsGetEndToEndTests — W4.2 TDD-first E2E tests for local-unix get.
//
// T08: e2e_localUnixGet_returnsPlaintext
//      Boot a brokerd with mock vault containing test-key → "hello-world",
//      dispatch secret.get over the wire, assert result is .string("hello-world").
//
// T09: e2e_localUnixGet_unknownScope_returnsScopeDenied
//      Non-allowlisted scope still denied (W4.1 behavior preserved).
//
// Spec UUID: e8c4a921-7d3b-4f5e-9a2c-1d6b8f4e3a91

@Suite("SecretsGetEndToEnd")
struct SecretsGetEndToEndTests {

    // MARK: - T08

    @Test("T08 e2e_localUnixGet_returnsPlaintext — result is string not ephemeralToken object")
    func test_t08_e2e_localUnixGet_returnsPlaintext() async throws {
        let stack = try await E2ESupport.make(
            scopeAllowlist: ["test-key", "ovh/OVH_APP_KEY", "brevo/BREVO_API_KEY", "github/GH_PAT"]
        )
        defer { Task { await E2ESupport.tearDown(stack) } }
        try await stack.daemon.start()

        // Seed the in-memory vault
        await stack.bwClient.seedFakeEntry(name: "test-key", fields: ["value": "hello-world"])

        // Dispatch via BrokerWireDispatcher (in-process, no actual socket)
        let dispatcher = BrokerWireDispatcher(daemon: stack.daemon, bridge: await stack.daemon.bridge)
        let req = WireRequest(
            method: "secret.get",
            params: .object(["name": .string("test-key")]),
            id: "t08"
        )
        let response = await dispatcher.dispatch(req, peerUid: UInt32(geteuid()))

        // T08: result must be .string("hello-world") — not an object
        #expect(response.error == nil, "T08: no error expected for allowed scope and valid vault entry")
        guard let result = response.result else {
            Issue.record("T08 FAIL: response.result is nil")
            return
        }
        guard case let .string(value) = result else {
            Issue.record("T08 FAIL: expected result .string, got \(result) — wireDecodeFailed would occur in client")
            return
        }
        #expect(value == "hello-world", "T08: vault value must match")

        // Confirm audit row was written
        let rows = await stack.audit.all()
        #expect(rows.contains(where: { $0.allow == .allow }),
                "T08: at least one allow audit row must be written")
    }

    // MARK: - T09

    @Test("T09 e2e_localUnixGet_unknownScope_returnsScopeDenied — W4.1 regression preserved")
    func test_t09_e2e_localUnixGet_unknownScope_returnsDenied() async throws {
        let stack = try await E2ESupport.make(
            // Allowlist does NOT include "forbidden-scope"
            scopeAllowlist: ["ovh/OVH_APP_KEY", "brevo/BREVO_API_KEY"]
        )
        defer { Task { await E2ESupport.tearDown(stack) } }
        try await stack.daemon.start()

        let dispatcher = BrokerWireDispatcher(daemon: stack.daemon, bridge: await stack.daemon.bridge)
        let req = WireRequest(
            method: "secret.get",
            params: .object(["name": .string("forbidden-scope")]),
            id: "t09"
        )
        let response = await dispatcher.dispatch(req, peerUid: UInt32(geteuid()))

        // T09: non-allowlisted scope must be denied (W4.1 ScopeValidator gate preserved)
        #expect(response.result == nil, "T09: denied scope must not produce a result")
        #expect(response.error != nil, "T09: denied scope must produce an error")
        let errCode = response.error?.code
        let isScopeDeny = errCode == WireErrorCode.scopeViolation || errCode == WireErrorCode.denied
        #expect(isScopeDeny,
                "T09: error code must be scope-violation or denied, got \(String(describing: errCode))")
    }
}
