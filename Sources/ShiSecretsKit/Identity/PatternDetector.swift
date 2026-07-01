// PatternDetector — selects the per-system identity deployment pattern by
// probing the vault's capability surface (W6.5c, F-PSA-2).
//
// Three patterns ship together; this detector distinguishes the two that are
// auto-detectable:
//
//   Pattern A — Bitwarden Secrets Manager machine_accounts (`client_credentials`
//               grant + Project scopes). Preferred when the server exposes the
//               Secrets Manager API.
//   Pattern B — per-USER Bitwarden accounts on stock Vaultwarden (default today).
//               Fallback when Secrets Manager is absent — this is what stock
//               Vaultwarden deployments get.
//   Pattern C — Hanko-issued short-lived tokens. Opt-in only via `--via-hanko`
//               (composes with W10); NOT auto-detected here.
//
// The network probe is abstracted behind `VaultCapabilityProbe` so the decision
// logic is pure + unit-testable with zero network I/O. The live probe fails
// closed to Pattern B on any error (stock Vaultwarden is the safe default).

import Foundation

/// The per-system identity deployment pattern.
public enum DeploymentPattern: String, Sendable, Equatable {
    /// Bitwarden Secrets Manager machine_accounts.
    case a
    /// Per-USER Bitwarden accounts on stock Vaultwarden (default fallback).
    case b
}

/// Abstracts the capability probe so `PatternDetector` does no network I/O
/// directly — tests inject a stub; production injects `LiveVaultCapabilityProbe`.
public protocol VaultCapabilityProbe: Sendable {
    /// Returns `true` iff the server exposes the Bitwarden Secrets Manager API.
    func secretsManagerAvailable() async -> Bool
}

/// Decides the deployment pattern from a capability probe.
public struct PatternDetector: Sendable {

    private let probe: any VaultCapabilityProbe

    public init(probe: any VaultCapabilityProbe) {
        self.probe = probe
    }

    /// Probe the server and select the pattern. Secrets Manager present → A,
    /// otherwise B (stock Vaultwarden fallback).
    public func detect() async -> DeploymentPattern {
        if await probe.secretsManagerAvailable() {
            return .a
        }
        return .b
    }
}

/// Live capability probe — best-effort HTTP probe of the Secrets Manager surface.
///
/// Fails CLOSED to "unavailable" (→ Pattern B) on any network/decoding error,
/// because stock Vaultwarden (Pattern B) is the safe, broadly-compatible default.
public struct LiveVaultCapabilityProbe: VaultCapabilityProbe {

    private let serverURL: URL
    private let session: URLSession
    private let timeout: TimeInterval

    public init(serverURL: URL, session: URLSession = .shared, timeout: TimeInterval = 5) {
        self.serverURL = serverURL
        self.session = session
        self.timeout = timeout
    }

    public func secretsManagerAvailable() async -> Bool {
        // The Secrets Manager API lives under `/api/organizations`.
        // Probing anonymously (no auth token) distinguishes the two cases:
        //
        //   401 — route IS registered; the server knows this endpoint and
        //          requires authentication. This is the definitive signal that
        //          Bitwarden Secrets Manager is present (→ Pattern A).
        //
        //   404 — route is NOT registered at all; stock Vaultwarden without
        //          the Secrets Manager feature flag returns 404 for every unknown
        //          path. This means Secrets Manager is absent (→ Pattern B).
        //
        //   Any other status (200, 5xx, 3xx…) is ambiguous for an anonymous
        //   probe; we fail closed to Pattern B (stock Vaultwarden is the safe,
        //   broadly-compatible default).
        var request = URLRequest(url: serverURL.appendingPathComponent("api/organizations"))
        request.httpMethod = "GET"
        request.timeoutInterval = timeout
        do {
            let (_, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse else { return false }
            // 401 → route present + auth wall → Secrets Manager live → Pattern A.
            return http.statusCode == 401
        } catch {
            // Network / TLS / timeout error — fail closed to Pattern B.
            ShikkiSecretsLogger().warning(
                """
                {"event":"vault-capability-probe-fallback","server_url":"\(serverURL.absoluteString)","error":"\(String(describing: error).replacingOccurrences(of: "\"", with: "'"))","fallback_pattern":"B"}
                """
            )
            return false
        }
    }
}
