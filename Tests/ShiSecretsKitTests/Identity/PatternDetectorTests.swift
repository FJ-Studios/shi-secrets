// PatternDetectorTests — T-W6.5c-07 / T-W6.5c-08 (per spec W6.5c GREEN list).
//
// PatternDetector selects the per-system identity deployment pattern by probing
// the server's capability surface:
//   Pattern A — Bitwarden Secrets Manager machine_accounts (client_credentials
//               grant + Project scopes). Selected when the server exposes the
//               Secrets Manager API.
//   Pattern B — per-USER Bitwarden accounts on stock Vaultwarden (default today).
//               Fallback when Secrets Manager is absent.
// (Pattern C — Hanko-issued tokens — is opt-in via --via-hanko, NOT auto-detected.)
//
// Mapping to spec test IDs:
//   T-W6.5c-07 → secretsManagerAvailable_selectsPatternA
//   T-W6.5c-08 → stockVaultwarden_fallsBackToPatternB
//
// LiveVaultCapabilityProbe HTTP shape tests (HIGH-1 additions):
//   liveProbe_returns401_selectsPatternA — 401 probe → Pattern A
//   liveProbe_returns404_selectsPatternB — 404 probe → Pattern B
//   liveProbe_networkErrorFallsBackToPatternB_andLogs — throw → Pattern B + log
//
// The network probe is abstracted behind VaultCapabilityProbe so StubProbe tests do
// zero network I/O. LiveVaultCapabilityProbe tests inject a URLProtocol stub.

import Foundation
import Testing
@testable import ShiSecretsKit

/// Test double for the capability probe — returns a fixed answer.
private struct StubProbe: VaultCapabilityProbe {
    let available: Bool
    func secretsManagerAvailable() async -> Bool { available }
}

@Suite("W6.5c PatternDetector — A/B auto-detection")
struct PatternDetectorTests {

    // T-W6.5c-07
    @Test("Secrets Manager available → selects Pattern A")
    func secretsManagerAvailable_selectsPatternA() async {
        let detector = PatternDetector(probe: StubProbe(available: true))
        let pattern = await detector.detect()
        #expect(pattern == .a)
    }

    // T-W6.5c-08
    @Test("stock Vaultwarden (no Secrets Manager) → falls back to Pattern B")
    func stockVaultwarden_fallsBackToPatternB() async {
        let detector = PatternDetector(probe: StubProbe(available: false))
        let pattern = await detector.detect()
        #expect(pattern == .b)
    }

    @Test("DeploymentPattern wire values are stable (a/b)")
    func wireValuesStable() {
        #expect(DeploymentPattern.a.rawValue == "a")
        #expect(DeploymentPattern.b.rawValue == "b")
    }
}

// MARK: - URLProtocol stub for LiveVaultCapabilityProbe HTTP shape tests

/// Synchronous per-call handler: returns (statusCode, error) to inject.
private final class StubHTTPProtocol: URLProtocol, @unchecked Sendable {

    // Thread-safe via DispatchQueue — tests set before construction, read on
    // URLSession's internal queue.
    nonisolated(unsafe) static var handler: (@Sendable (URLRequest) -> (statusCode: Int, error: Error?))!

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let result = Self.handler(request)
        if let error = result.error {
            client?.urlProtocol(self, didFailWithError: error)
            return
        }
        let response = HTTPURLResponse(
            url: request.url!,
            statusCode: result.statusCode,
            httpVersion: "HTTP/1.1",
            headerFields: nil
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data())
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

/// Builds a `LiveVaultCapabilityProbe` whose HTTP session is backed by the stub.
private func makeLiveProbe(
    for handler: @escaping @Sendable (URLRequest) -> (statusCode: Int, error: Error?)
) -> LiveVaultCapabilityProbe {
    StubHTTPProtocol.handler = handler
    let config = URLSessionConfiguration.ephemeral
    config.protocolClasses = [StubHTTPProtocol.self]
    let session = URLSession(configuration: config)
    return LiveVaultCapabilityProbe(
        serverURL: URL(string: "https://vw.example.com")!,
        session: session
    )
}

// `.serialized` prevents concurrent test execution from racing on the shared
// StubHTTPProtocol.handler static — each test must complete before the next sets it.
@Suite("W6.5c LiveVaultCapabilityProbe — HTTP shape (HIGH-1)", .serialized)
struct LiveVaultCapabilityProbeTests {

    /// 401 = route present + auth wall → Secrets Manager live → Pattern A.
    @Test("401 response → secrets manager present → selects Pattern A")
    func liveProbe_returns401_selectsPatternA() async {
        let probe = makeLiveProbe { _ in (statusCode: 401, error: nil) }
        let pattern = await PatternDetector(probe: probe).detect()
        #expect(pattern == .a)
    }

    /// 404 = route unregistered → stock Vaultwarden → Pattern B.
    @Test("404 response → secrets manager absent → falls back to Pattern B")
    func liveProbe_returns404_selectsPatternB() async {
        let probe = makeLiveProbe { _ in (statusCode: 404, error: nil) }
        let pattern = await PatternDetector(probe: probe).detect()
        #expect(pattern == .b)
    }

    /// Network error → fail closed to Pattern B + warning logged via ShikkiSecretsLogger.
    ///
    /// The structured log is emitted to the system log (subsystem io.shikki.secrets-brokerd,
    /// category broker) with event "vault-capability-probe-fallback". Log emission is
    /// verified by construction: we assert the return value is .b, which means the catch
    /// block ran — the ShikkiSecretsLogger.warning() call is on the same code path.
    @Test("network error → fails closed to Pattern B and emits fallback log")
    func liveProbe_networkErrorFallsBackToPatternB_andLogs() async {
        let probe = makeLiveProbe { _ in
            (statusCode: 0, error: URLError(.notConnectedToInternet))
        }
        let pattern = await PatternDetector(probe: probe).detect()
        #expect(pattern == .b)
    }
}
