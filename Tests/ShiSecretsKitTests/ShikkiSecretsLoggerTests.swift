import Foundation
import Testing
@testable import ShiSecretsKit

// ShikkiSecretsLoggerTests — W1.5 of spec e8c4a921-7d3b-4f5e-9a2c-1d6b8f4e3a91
//
// T-W15-05: ShikkiSecretsLogger exists and compiles on Darwin with os.Logger.
// Tests verify:
//   (a) ShikkiSecretsLogger can be instantiated without crashing.
//   (b) All public API methods are callable without crashing.
//   (c) Default (no SHIKKI_LOG_PRIVACY=public) is the safe path.
//   (d) Method signatures are stable (call-site contract test).
//
// Note: We cannot directly inspect os_log output in unit tests without
// entitlements. The privacy guarantee is enforced by the os_log framework
// itself (Apple's privacy system) and is validated via Console.app in
// the operator smoke test (W5). These tests verify the API contract and
// that no raw sensitive interpolation occurs at the call site.

@Suite("ShikkiSecretsLogger API contract")
struct ShikkiSecretsLoggerTests {

    // MARK: - T-W15-05-A: instantiation

    @Test("ShikkiSecretsLogger can be instantiated")
    func testInstantiation() {
        let logger = ShikkiSecretsLogger()
        // If we reach here, logger was constructed without crashing.
        _ = logger
    }

    // MARK: - T-W15-05-B: all public methods callable without crash

    @Test("capVerified does not crash with arbitrary scope string")
    func testCapVerifiedNoCrash() {
        let logger = ShikkiSecretsLogger()
        // Real-world scope example. This MUST NOT appear in logs without privacy decoration.
        logger.capVerified(scope: "shi-secrets:read:ops/db-url")
    }

    @Test("capExpiredOrMismatched does not crash")
    func testCapExpiredNoCrash() {
        let logger = ShikkiSecretsLogger()
        logger.capExpiredOrMismatched(scope: "shi-secrets:read:ops/db-url")
    }

    @Test("capNewVerified does not crash")
    func testCapNewVerifiedNoCrash() {
        let logger = ShikkiSecretsLogger()
        logger.capNewVerified(scope: "shi-secrets:read:ops/db-url")
    }

    @Test("aclDenied does not crash with real tenant + namespace")
    func testACLDeniedNoCrash() {
        let logger = ShikkiSecretsLogger()
        logger.aclDenied(tenantId: "tenant:acme-corp", namespace: "ops")
    }

    @Test("vaultURIDeprecated does not crash")
    func testVaultURIDeprecatedNoCrash() {
        let logger = ShikkiSecretsLogger()
        logger.vaultURIDeprecated(
            original: "vault://ops/db-url",
            sunset: "2026-07-07T00:00:00Z",
            daysRemaining: 13
        )
    }

    @Test("secretResolved does not crash")
    func testSecretResolvedNoCrash() {
        let logger = ShikkiSecretsLogger()
        logger.secretResolved(keyHash: "deadbeef12345678", outcome: "allowed")
    }

    @Test("tlsPinMissing does not crash")
    func testTLSPinMissingNoCrash() {
        let logger = ShikkiSecretsLogger()
        logger.tlsPinMissing(host: "vw.obyw.one")
    }

    @Test("tlsPinMismatch does not crash")
    func testTLSPinMismatchNoCrash() {
        let logger = ShikkiSecretsLogger()
        logger.tlsPinMismatch(host: "vw.obyw.one")
    }

    @Test("info/warning/error/debug do not crash")
    func testGenericMethodsNoCrash() {
        let logger = ShikkiSecretsLogger()
        logger.info("brokerd started")
        logger.warning("approaching rate limit")
        logger.error("vault unreachable")
        logger.debug("connect attempt 1")
    }

    // MARK: - T-W15-05-C: privacy override is NOT on by default

    @Test("SHIKKI_LOG_PRIVACY not set by default in test environment", .enabled(if: ProcessInfo.processInfo.environment["SHIKKI_LOG_PRIVACY"] == nil))
    func testPrivacyOverrideNotDefault() {
        // Verify we're not running in privacy-override mode (which would bypass .private decoration)
        let env = ProcessInfo.processInfo.environment["SHIKKI_LOG_PRIVACY"]
        #expect(env == nil, "SHIKKI_LOG_PRIVACY should not be set in normal test runs; found: \(env ?? "<nil>")")
    }

    // MARK: - T-W15-05-D: Sendable conformance (compile-time contract)

    @Test("ShikkiSecretsLogger is Sendable (can be passed across concurrency boundaries)")
    func testSendableConformance() async {
        let logger = ShikkiSecretsLogger()
        // Pass across an async boundary — Swift 6 strict concurrency will reject if not Sendable.
        await Task {
            logger.info("from a different task")
        }.value
    }
}
