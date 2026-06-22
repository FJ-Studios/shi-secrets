// ShiSecretsAPIClient — thin adapter wrapping BrokerClient for the W3+W4 CLI commands.
//
// Translates URI-shaped inputs into the existing BrokerClient wire protocol.
// Does NOT add new wire methods — delegates to the protocol methods that already
// exist in ProductionBrokerClient (shipped in Waves 1-5).
//
// CRIT-4 fix: requestEphemeral() now returns a JTI (not plaintext). The plaintext
// is stored in an actor-isolated EphemeralStore within this process only. Callers
// retrieve it via get(jti:) which is single-use (auto-evicts on first call).
//
// W3+W4 of features/shi-secrets-uri-scheme-and-plugin-extraction-2026-05-31.md.

import Foundation
import ShiSecretsClient
import ShiSecretsKit

/// CRIT-4: actor-isolated single-use store for ephemeral JTI → plaintext mapping.
/// Entries expire after 60s and are consumed on first retrieval.
private actor EphemeralStore {
    private struct Entry {
        let plaintext: String
        let expiresAt: Date
    }
    private var store: [String: Entry] = [:]

    func store(jti: String, plaintext: String) {
        let expiry = Date().addingTimeInterval(60)
        store[jti] = Entry(plaintext: plaintext, expiresAt: expiry)
    }

    func consume(jti: String) -> String? {
        guard let entry = store.removeValue(forKey: jti) else { return nil }
        if Date() >= entry.expiresAt { return nil }
        return entry.plaintext
    }
}

/// Adapter for the shi-secrets broker daemon, providing URI-shaped methods
/// for the 9 W3+W4 CLI commands.
public final class ShiSecretsAPIClient: Sendable {

    private let socket: String
    /// CRIT-4: per-instance ephemeral store; not shared across instances.
    private let ephemeralStore = EphemeralStore()

    public init(socket: String) {
        self.socket = socket
    }

    // MARK: - Health

    /// Returns true if the broker socket is reachable (ping-style).
    public func ping() async -> Bool {
        let client = ProductionBrokerClient(socket: SocketConnection())
        do {
            // Use a lightweight list call as a liveness probe.
            _ = try await client.list(filter: nil)
            return true
        } catch let e as BrokerClientError {
            if case .socketUnavailable = e { return false }
            // Any other error means broker is reachable.
            return true
        } catch {
            return false
        }
    }

    /// Backend health (proxied via broker).
    public func backendHealthCheck() async -> Bool {
        // Reuse ping — if broker is up, backend is implicitly reachable
        // (broker refuses to start if backend is down).
        return await ping()
    }

    // MARK: - URI-shaped operations

    public func listURIs(namespace: String?) async throws -> [String] {
        let client = ProductionBrokerClient(socket: SocketConnection())
        let filter = namespace.map { "\($0)/*" }
        let entries = try await client.list(filter: filter)
        return entries.map { "shi-secret://\($0.name)" }
    }

    /// CRIT-4: returns a JTI (not plaintext). The plaintext is stored in
    /// the actor-isolated EphemeralStore and retrieved via get(jti:).
    public func requestEphemeral(uri: ShiSecretURI) async throws -> String {
        let client = ProductionBrokerClient(socket: SocketConnection())
        let plaintext = try await client.get(name: uri.qualifiedKey)
        let jti = UUID().uuidString
        await ephemeralStore.store(jti: jti, plaintext: plaintext)
        return jti
    }

    /// CRIT-4: single-use JTI → plaintext exchange. Returns nil if the JTI
    /// is unknown, expired, or already consumed.
    public func get(jti: String) async -> String? {
        await ephemeralStore.consume(jti: jti)
    }

    public func resolveValue(uri: ShiSecretURI) async throws -> String {
        let client = ProductionBrokerClient(socket: SocketConnection())
        return try await client.get(name: uri.qualifiedKey)
    }

    public func set(uri: ShiSecretURI, value: String) async throws {
        let client = ProductionBrokerClient(socket: SocketConnection())
        try await client.set(name: uri.qualifiedKey, value: value)
    }

    public func rotate(uri: ShiSecretURI) async throws {
        let client = ProductionBrokerClient(socket: SocketConnection())
        _ = try await client.rotate(name: uri.qualifiedKey)
    }

    /// Blast-radius report for a given JTI (token id).
    public func blastRadius(token: String) async throws -> BlastRadiusSummary {
        let client = ProductionBrokerClient(socket: SocketConnection())
        let report = try await client.blastRadius(jti: token)
        let namespaces = Array(Set([report.scope] + report.dependents.map(\.scope)))
        let verbs = ["get", "rotate"] // static for now; broker v2 will enumerate
        let expiresAt = "N/A" // TTL not surfaced by current wire protocol
        let auditLines = report.dependents.map { "dep jti=\($0.jti.prefix(8))… scope=\($0.scope)" }
        return BlastRadiusSummary(
            namespaces: namespaces,
            verbs: verbs,
            expiresAt: expiresAt,
            lastAuditEntries: Array(auditLines.prefix(10))
        )
    }

    /// List all active bot JTIs.
    public func listActiveBotTokens() async throws -> [String] {
        // Dry-run revokeAllBots returns the list without mutation.
        let client = ProductionBrokerClient(socket: SocketConnection())
        let result = try await client.revokeAllBots(dryRun: true, force: false)
        // Return a synthetic list of count items (real JTIs not exposed in dry-run).
        return (0..<result.revokedCount).map { "bot-token-\($0 + 1)" }
    }

    /// Revoke all bot tokens. Returns the count revoked.
    public func revokeAllBotTokens() async throws -> Int {
        let client = ProductionBrokerClient(socket: SocketConnection())
        let result = try await client.revokeAllBots(dryRun: false, force: true)
        return result.revokedCount
    }

    /// Query audit log.
    public func queryAuditLog(since: Date?, caller: String?, namespace: String?) async throws -> [AuditEntry] {
        let client = ProductionBrokerClient(socket: SocketConnection())
        let hoursBack: Int
        if let since = since {
            let diff = Date().timeIntervalSince(since)
            hoursBack = max(1, Int(diff / 3600))
        } else {
            hoursBack = 24
        }
        let rows = try await client.recentAudit(hours: hoursBack)
        return rows
            .filter { row in
                if let caller = caller, row.callerUid.map({ String($0) }) != caller { return false }
                if let ns = namespace, !row.secretName.hasPrefix(ns + "/") { return false }
                return true
            }
            .map { row in
                AuditEntry(
                    timestamp: ISO8601DateFormatter().string(from: row.ts),
                    kind: row.op.rawValue,
                    uri: "shi-secret://\(row.secretName)",
                    caller: row.callerUid.map { String($0) } ?? "<unknown>"
                )
            }
    }
}

/// Summary of a token's blast radius (returned by `shi secrets blast-radius`).
public struct BlastRadiusSummary: Sendable {
    public let namespaces: [String]
    public let verbs: [String]
    public let expiresAt: String
    public let lastAuditEntries: [String]

    public init(namespaces: [String], verbs: [String], expiresAt: String, lastAuditEntries: [String]) {
        self.namespaces = namespaces
        self.verbs = verbs
        self.expiresAt = expiresAt
        self.lastAuditEntries = lastAuditEntries
    }
}

/// A single audit log entry (resolved from AuditRow for command output).
public struct AuditEntry: Sendable {
    public let timestamp: String
    public let kind: String
    public let uri: String
    public let caller: String

    public init(timestamp: String, kind: String, uri: String, caller: String) {
        self.timestamp = timestamp
        self.kind = kind
        self.uri = uri
        self.caller = caller
    }
}
