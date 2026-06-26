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

// RequestGatewayTests — Wave A4 TDD-first tests.
//
// Verifies that RequestGateway.authorise correctly:
//   T-A4-01  valid scope + active bwSession → .allow with captured preMintSessionEpoch
//   T-A4-02  scope too long → .deny(.scopeTooLong) + audit row written
//   T-A4-03  scope pattern blocked → .deny(.scopePatternDenied) + audit row written
//   T-A4-04  blast-radius blocked → .deny(.scopeBlastRadiusDenied) + audit row written
//   T-A4-05  bw session invalid → .deny(.brokerSessionInvalid) + audit row written
//   T-A4-06  audit row is written BEFORE returning deny
//   T-A4-07  BrokerDaemon no longer has a scopeValidator field (structural check)

@Suite("RequestGateway")
struct RequestGatewayTests {

    // MARK: - Helpers

    /// Build a RequestGateway with the given allowlist and session state.
    private func makeGateway(
        allowlist: [String] = ["ovh/OVH_APP_KEY", "brevo/BREVO_API_KEY"],
        sessionValid: Bool = true,
        systemScopePolicy: ScopePolicy? = nil
    ) async throws -> (RequestGateway, AuditWriter, InMemoryBWClient) {
        let audit = AuditWriter()
        let scopeValidator = try ScopeValidator(allowlist: allowlist)
        let bwClient = InMemoryBWClient()
        if sessionValid {
            await bwClient.activate()
        }
        let gateway = RequestGateway(
            scopeValidator: scopeValidator,
            systemScopePolicy: systemScopePolicy,
            bwClient: bwClient,
            audit: audit
        )
        return (gateway, audit, bwClient)
    }

    private func makeRequest(scope: String = "ovh/OVH_APP_KEY") -> BrokerRequest {
        BrokerRequest(sub: "claude@tusken", scope: scope, op: .read, ttl: 600, toolName: nil)
    }

    private func makeWrapped() -> WrappedRequest {
        WrappedRequest(
            peerUid: UInt32(geteuid()),
            transport: .unix,
            llmTouched: false,
            payload: Data()
        )
    }

    // MARK: - T-A4-01

    @Test("T-A4-01: gateway_authorise_validScopeAndBwSession_returnsAllow_withSessionEpoch")
    func gateway_authorise_validScopeAndBwSession_returnsAllow_withSessionEpoch() async throws {
        let (gateway, audit, _) = try await makeGateway()
        let request = makeRequest()
        let wrapped = makeWrapped()

        let outcome = await gateway.authorise(request, wrapped: wrapped, now: Date())

        guard case .allow(let epoch) = outcome else {
            Issue.record("expected .allow, got \(outcome)")
            return
        }
        // session epoch should be captured (0 for fresh InMemoryBWClient)
        #expect(epoch == 0)
        // No audit row for allowed requests (audit row comes from BrokerDaemon on allow)
        let rows = await audit.all()
        #expect(rows.isEmpty, "gateway must not write audit rows for allowed requests")
    }

    // MARK: - T-A4-02

    @Test("T-A4-02: gateway_authorise_scopeTooLong_returnsDeny_scopeTooLong")
    func gateway_authorise_scopeTooLong_returnsDeny_scopeTooLong() async throws {
        let (gateway, audit, _) = try await makeGateway(allowlist: ["**"])
        let overlong = String(repeating: "a", count: ScopeValidator.maxScopeLength + 1)
        let request = makeRequest(scope: overlong)
        let wrapped = makeWrapped()

        let outcome = await gateway.authorise(request, wrapped: wrapped, now: Date())

        guard case .deny(let reason) = outcome else {
            Issue.record("expected .deny, got \(outcome)")
            return
        }
        #expect(reason == .scopeTooLong)
        let rows = await audit.all()
        #expect(rows.count == 1, "must write one deny audit row")
        #expect(rows.first?.allow == .deny)
        #expect(rows.first?.reason == .scopeTooLong)
    }

    // MARK: - T-A4-03

    @Test("T-A4-03: gateway_authorise_scopePatternBlocked_returnsDeny_scopePatternDenied")
    func gateway_authorise_scopePatternBlocked_returnsDeny_scopePatternDenied() async throws {
        // allowlist does NOT contain "blocked/SECRET"
        let (gateway, audit, _) = try await makeGateway(allowlist: ["ovh/OVH_APP_KEY"])
        let request = makeRequest(scope: "blocked/SECRET")
        let wrapped = makeWrapped()

        let outcome = await gateway.authorise(request, wrapped: wrapped, now: Date())

        guard case .deny(let reason) = outcome else {
            Issue.record("expected .deny, got \(outcome)")
            return
        }
        #expect(reason == .scopePatternDenied)
        let rows = await audit.all()
        #expect(rows.count == 1)
        #expect(rows.first?.reason == .scopePatternDenied)
    }

    // MARK: - T-A4-04

    @Test("T-A4-04: gateway_authorise_blastRadiusBlocked_returnsDeny_scopeBlastRadiusDenied")
    func gateway_authorise_blastRadiusBlocked_returnsDeny_scopeBlastRadiusDenied() async throws {
        // Create a ScopePolicy that only allows "shi/system/self/**" + "shi/shared/**"
        // "ovh/OVH_APP_KEY" falls outside those prefixes → canRead returns false.
        let policy = ScopePolicy(systemName: "self")
        // allowlist permits "**" so ScopeValidator passes, but ScopePolicy blocks
        let (gateway, audit, _) = try await makeGateway(
            allowlist: ["**"],
            systemScopePolicy: policy
        )
        let request = makeRequest(scope: "ovh/OVH_APP_KEY")
        let wrapped = makeWrapped()

        let outcome = await gateway.authorise(request, wrapped: wrapped, now: Date())

        guard case .deny(let reason) = outcome else {
            Issue.record("expected .deny, got \(outcome)")
            return
        }
        #expect(reason == .scopeBlastRadiusDenied)
        let rows = await audit.all()
        #expect(rows.count == 1)
        #expect(rows.first?.reason == .scopeBlastRadiusDenied)
    }

    // MARK: - T-A4-05

    @Test("T-A4-05: gateway_authorise_bwSessionInvalid_returnsDeny_brokerSessionInvalid")
    func gateway_authorise_bwSessionInvalid_returnsDeny_brokerSessionInvalid() async throws {
        let (gateway, audit, _) = try await makeGateway(
            allowlist: ["ovh/OVH_APP_KEY"],
            sessionValid: false    // session NOT activated
        )
        let request = makeRequest()
        let wrapped = makeWrapped()

        let outcome = await gateway.authorise(request, wrapped: wrapped, now: Date())

        guard case .deny(let reason) = outcome else {
            Issue.record("expected .deny, got \(outcome)")
            return
        }
        #expect(reason == .brokerSessionInvalid)
        let rows = await audit.all()
        #expect(rows.count == 1)
        #expect(rows.first?.reason == .brokerSessionInvalid)
    }

    // MARK: - T-A4-06

    @Test("T-A4-06: gateway_authorise_writesAuditRowBeforeReturningDeny")
    func gateway_authorise_writesAuditRowBeforeReturningDeny() async throws {
        // Use a blocked scope to trigger deny
        let (gateway, audit, _) = try await makeGateway(allowlist: ["ovh/OVH_APP_KEY"])
        let request = makeRequest(scope: "other/SECRET")
        let wrapped = makeWrapped()
        let now = Date(timeIntervalSince1970: 1_777_000_000)

        let auditCountBefore = await audit.count()
        let outcome = await gateway.authorise(request, wrapped: wrapped, now: now)

        // Must be deny
        guard case .deny = outcome else {
            Issue.record("expected .deny, got \(outcome)")
            return
        }
        let auditCountAfter = await audit.count()
        #expect(auditCountAfter > auditCountBefore, "audit row must be written before deny is returned")

        // The row's timestamp must match `now` (written synchronously before return)
        let rows = await audit.all()
        #expect(rows.last?.ts == now, "audit row ts must match the `now` passed to authorise")
        #expect(rows.last?.allow == .deny)
    }

    // MARK: - T-A4-07

    @Test("T-A4-07: brokerDaemon_handleRequest_delegatesScopeChecks_toGateway")
    func brokerDaemon_handleRequest_delegatesScopeChecks_toGateway() async throws {
        // Structural check: BrokerDaemon must expose a `gateway: RequestGateway` field
        // and must NOT have a `scopeValidator` field after Wave A4 extraction.
        //
        // We verify at compile-time via Mirror reflection:
        //   - `gateway` must be present
        //   - `scopeValidator` must NOT be present (moved to RequestGateway)
        let kernel = ShikkiKernel()
        let audit = AuditWriter()
        let seams = SeamsWriter()
        let registry = TokenRegistry()
        let drivers = DriverRegistry()
        let engine = RotationEngine(drivers: drivers, audit: audit, seams: seams, registry: registry)
        let verifier = ManifestVerifier(pinnedPublicKey: Curve25519.Signing.PrivateKey().publicKey)
        let manifestStore = ManifestStore(verifier: verifier, seams: seams)
        let scopeValidator = try ScopeValidator(allowlist: ["ovh/OVH_APP_KEY"])
        let bridge = MCPBridge()
        let socket = UnixSocketServer(
            config: UnixSocketConfig(
                socketPath: "/tmp/sh-gw-\(UUID().uuidString.prefix(8)).s",
                expectedMode: 0o600,
                expectedUid: UInt32(geteuid())
            )
        )
        let bwClient = InMemoryBWClient()
        await bwClient.activate()
        let minter = TokenMinter(
            registry: registry,
            signingKey: Curve25519.Signing.PrivateKey(),
            toolManifest: []
        )
        let gateway = RequestGateway(
            scopeValidator: scopeValidator,
            bwClient: bwClient,
            audit: audit
        )
        let daemon = BrokerDaemon(
            kernel: kernel, audit: audit, seams: seams, registry: registry,
            drivers: drivers, engine: engine,
            manifestStore: manifestStore, gateway: gateway,
            bridge: bridge, socket: socket, bwClient: bwClient, minter: minter,
            bootstrap: StubBootstrapProvider()
        )

        // gateway field must exist
        let mirror = Mirror(reflecting: daemon)
        let hasGateway = mirror.children.contains { $0.label == "gateway" }
        #expect(hasGateway, "BrokerDaemon must expose a `gateway: RequestGateway` field after Wave A4")

        // scopeValidator must NOT exist directly on BrokerDaemon
        let hasScopeValidator = mirror.children.contains { $0.label == "scopeValidator" }
        #expect(!hasScopeValidator, "BrokerDaemon must NOT have a `scopeValidator` field after Wave A4 — it moved to RequestGateway")
    }
}
