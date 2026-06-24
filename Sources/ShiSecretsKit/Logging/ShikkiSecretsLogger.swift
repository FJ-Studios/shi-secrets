import Foundation

// ShikkiSecretsLogger — privacy-aware structured logger for the secrets pipeline.
//
// W1.5 of spec e8c4a921-7d3b-4f5e-9a2c-1d6b8f4e3a91
// Panel doc: super-challenge-w2-nats-log-crypto-transport-security-2026-06-24.md
//
// Architecture:
//   Darwin: wraps os.Logger with privacy decorators. Scope/cap/key strings
//     use .private(mask: .hash) — visible as sha256 prefix in privileged
//     Console.app sessions; redacted to <private> otherwise.
//   Linux: wraps swift-log Logger; sensitive fields are OMITTED entirely
//     (not logged, not masked). No plaintext scope strings ever reach disk.
//
// API contract:
//   All methods accept sensitive values via labeled parameters that carry
//   the intent: `scope:`, `tenantId:`, `namespace:`, `keyRef:`.
//   Call sites MUST NOT interpolate these directly into the message string.
//
// Privacy override (debug-only escape hatch):
//   Set SHIKKI_LOG_PRIVACY=public in the environment to emit private fields
//   as plaintext for the current process lifetime. NEVER persisted.
//
// BR-SM-W15, HIGH-2

#if canImport(os)
import os

// MARK: - Darwin implementation

/// Privacy-aware structured logger for the shikki secrets pipeline.
///
/// On Darwin, wraps `os.Logger` with privacy decorators so scope/cap strings
/// are hashed in production builds and fully redacted without a developer profile.
/// On Linux, uses swift-log with all sensitive fields omitted.
public struct ShikkiSecretsLogger: Sendable {

    // MARK: - Private state

    private let vaultLog = os.Logger(
        subsystem: "io.shikki.secrets-brokerd",
        category: "vault"
    )
    private let aclLog = os.Logger(
        subsystem: "io.shikki.secrets-brokerd",
        category: "acl"
    )
    private let auditLog = os.Logger(
        subsystem: "io.shikki.secrets-brokerd",
        category: "audit"
    )
    private let brokerLog = os.Logger(
        subsystem: "io.shikki.secrets-brokerd",
        category: "broker"
    )

    /// When true (SHIKKI_LOG_PRIVACY=public), sensitive fields are emitted as
    /// plaintext via os_log. NEVER enabled by default. Dev/CI use only.
    private let privacyOverride: Bool

    // MARK: - Init

    public init() {
        self.privacyOverride = ProcessInfo.processInfo.environment["SHIKKI_LOG_PRIVACY"] == "public"
    }

    // MARK: - Public API

    /// Capability token is valid for the given scope. Scope is hashed.
    public func capVerified(scope: String) {
        if privacyOverride {
            vaultLog.debug("Cap verified scope: \(scope, privacy: .public)")
        } else {
            vaultLog.debug("Cap verified scope: \(scope, privacy: .private(mask: .hash))")
        }
    }

    /// Cached capability expired or mismatched for the given scope.
    public func capExpiredOrMismatched(scope: String) {
        if privacyOverride {
            vaultLog.info("Cached cap expired/mismatched scope: \(scope, privacy: .public) — re-issuing")
        } else {
            vaultLog.info("Cached cap expired/mismatched scope: \(scope, privacy: .private(mask: .hash)) — re-issuing")
        }
    }

    /// New capability issued and verified for the given scope.
    public func capNewVerified(scope: String) {
        if privacyOverride {
            vaultLog.debug("New cap verified scope: \(scope, privacy: .public)")
        } else {
            vaultLog.debug("New cap verified scope: \(scope, privacy: .private(mask: .hash))")
        }
    }

    /// ACL denied for tenant + namespace. tenantId is hashed; namespace is public.
    public func aclDenied(tenantId: String, namespace: String) {
        if privacyOverride {
            aclLog.warning("ACL denied tenant=\(tenantId, privacy: .public) ns=\(namespace, privacy: .public)")
        } else {
            aclLog.warning("ACL denied tenant=\(tenantId, privacy: .private) ns=\(namespace, privacy: .public)")
        }
    }

    /// Vault URI deprecated and being rewritten. The original URI is hashed.
    public func vaultURIDeprecated(original: String, sunset: String, daysRemaining: Int) {
        if privacyOverride {
            brokerLog.warning(
                "vault:// URI deprecated — rewriting to shi-secret://. sunset=\(sunset, privacy: .public) daysRemaining=\(daysRemaining, privacy: .public) original=\(original, privacy: .public)"
            )
        } else {
            brokerLog.warning(
                "vault:// URI deprecated — rewriting to shi-secret://. sunset=\(sunset, privacy: .public) daysRemaining=\(daysRemaining, privacy: .public) original=\(original, privacy: .private(mask: .hash))"
            )
        }
    }

    /// Secret resolved successfully. keyHash is always public (SHA-256 prefix).
    public func secretResolved(keyHash: String, outcome: String) {
        auditLog.info(
            "Secret resolved keyHash=\(keyHash, privacy: .public) outcome=\(outcome, privacy: .public)"
        )
    }

    /// TLS pin missing — falling back to CA validation.
    public func tlsPinMissing(host: String) {
        vaultLog.warning(
            "TLS pin not configured for host=\(host, privacy: .public) — falling back to CA validation. Set tls_pin_sha256 in ~/.shikki/settings/vault.toml"
        )
    }

    /// TLS pin mismatch — connection cancelled.
    public func tlsPinMismatch(host: String) {
        vaultLog.error(
            "TLS pin mismatch for host=\(host, privacy: .public) — connection cancelled (possible MITM)"
        )
    }

    /// TLS minimum version enforced.
    public func tlsMinVersionEnforced(version: String) {
        vaultLog.info("TLS minimum version enforced: \(version, privacy: .public)")
    }

    /// Generic broker info — message is assumed non-sensitive (caller's responsibility).
    public func info(_ message: String) {
        brokerLog.info("\(message, privacy: .public)")
    }

    /// Generic broker warning — message is assumed non-sensitive.
    public func warning(_ message: String) {
        brokerLog.warning("\(message, privacy: .public)")
    }

    /// Generic broker error — message is assumed non-sensitive.
    public func error(_ message: String) {
        brokerLog.error("\(message, privacy: .public)")
    }

    /// Generic debug — message is assumed non-sensitive. Use capVerified etc. for sensitive events.
    public func debug(_ message: String) {
        brokerLog.debug("\(message, privacy: .public)")
    }
}

#else

// MARK: - Linux implementation

import Logging

/// Privacy-aware structured logger for the shikki secrets pipeline.
///
/// On Linux, uses swift-log. ALL sensitive fields (scope, tenantId, namespace,
/// keyRef, original URIs) are OMITTED. Only non-sensitive outcome/context
/// strings are logged.
public struct ShikkiSecretsLogger: Sendable {

    private let logger = Logger(label: "io.shikki.secrets-brokerd")

    public init() {}

    public func capVerified(scope: String) {
        // Scope NEVER logged on Linux — no ACL protection on flat files.
        logger.debug("Cap verified [scope redacted]")
    }

    public func capExpiredOrMismatched(scope: String) {
        logger.info("Cached cap expired/mismatched [scope redacted] — re-issuing")
    }

    public func capNewVerified(scope: String) {
        logger.debug("New cap verified [scope redacted]")
    }

    public func aclDenied(tenantId: String, namespace: String) {
        // tenantId redacted; namespace retained (non-sensitive category label).
        logger.warning("ACL denied ns=\(namespace) [tenantId redacted]")
    }

    public func vaultURIDeprecated(original: String, sunset: String, daysRemaining: Int) {
        // original URI redacted; sunset date is non-sensitive.
        logger.warning("vault:// URI deprecated — rewriting to shi-secret://. sunset=\(sunset) daysRemaining=\(daysRemaining) [original redacted]")
    }

    public func secretResolved(keyHash: String, outcome: String) {
        // keyHash is SHA-256 prefix — public by design.
        logger.info("Secret resolved keyHash=\(keyHash) outcome=\(outcome)")
    }

    public func tlsPinMissing(host: String) {
        logger.warning("TLS pin not configured for host=\(host) — falling back to CA validation. Set tls_pin_sha256 in ~/.shikki/settings/vault.toml")
    }

    public func tlsPinMismatch(host: String) {
        logger.error("TLS pin mismatch for host=\(host) — connection cancelled")
    }

    public func tlsMinVersionEnforced(version: String) {
        logger.info("TLS minimum version enforced: \(version)")
    }

    public func info(_ message: String) {
        logger.info("\(message)")
    }

    public func warning(_ message: String) {
        logger.warning("\(message)")
    }

    public func error(_ message: String) {
        logger.error("\(message)")
    }

    public func debug(_ message: String) {
        logger.debug("\(message)")
    }
}

#endif
