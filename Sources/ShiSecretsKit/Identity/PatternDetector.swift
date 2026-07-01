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
        // The Secrets Manager API lives under `/api/organizations/.../secrets`.
        // Stock Vaultwarden does not route the Secrets Manager surface and returns
        // 404; a Secrets-Manager-capable server returns 401 (auth required) — i.e.
        // the route EXISTS. We treat "route exists (not 404)" as available.
        var request = URLRequest(url: serverURL.appendingPathComponent("api/organizations"))
        request.httpMethod = "GET"
        request.timeoutInterval = timeout
        do {
            let (_, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse else { return false }
            // 404 → route absent → stock Vaultwarden → Pattern B.
            return http.statusCode != 404
        } catch {
            return false
        }
    }
}
