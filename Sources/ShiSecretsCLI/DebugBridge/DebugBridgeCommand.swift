// DebugBridgeCommand.swift — W7 KatagamiDebugBridge CLI verbs
//
// `shi debug-bridge <subcommand>` CLI surface.
// All subcommands are registered in SubcommandRegistry.
//
// Credential rule ([[feedback_no-credentials-in-env-vars]]):
//   client_id / client_secret → macOS Keychain only
//   Bearer token              → stdout only (caller caches in BridgeTokenCache actor)
//   NEVER: env vars, flat files, Postgres, /tmp
//
// Swift-only (SPM exec). No Python. Pure Swift 6 concurrency.

import Foundation
import ShiSecretsKit

// MARK: - DebugBridgeCommand (dispatcher)

/// Top-level `shi debug-bridge` command group.
/// Dispatches to sub-commands: token, revoke, key-rotate, key-compromise,
/// register-device, status, audit.
public struct DebugBridgeCommand {

    public static func main(args: [String]) async throws {
        guard let subcommand = args.first else {
            printHelp()
            return
        }
        let rest = Array(args.dropFirst())
        switch subcommand {
        case "token":           try await DebugBridgeTokenSubcommand.run(args: rest)
        case "revoke":          try await DebugBridgeRevokeSubcommand.run(args: rest)
        case "key-rotate":      try await DebugBridgeKeyRotateSubcommand.run(args: rest)
        case "key-compromise":  try await DebugBridgeKeyCompromiseSubcommand.run(args: rest)
        case "register-device": try await DebugBridgeRegisterDeviceSubcommand.run(args: rest)
        case "status":          try await DebugBridgeStatusSubcommand.run(args: rest)
        case "audit":           try await DebugBridgeAuditSubcommand.run(args: rest)
        default:
            fputs("shi debug-bridge: unknown subcommand '\(subcommand)'\n", stderr)
            printHelp()
        }
    }

    private static func printHelp() {
        print("""
        shi debug-bridge <subcommand> [options]

        Subcommands:
          token            Issue a KatagamiDebugBridge JWT from Keychain credentials
          revoke           Revoke a token (by jti, device, or --all)
          key-rotate       Rotate the Ed25519 signing key (grace period preserved)
          key-compromise   Emergency: retire key immediately, mass-revoke all tokens
          register-device  Register a device and store client credentials in Keychain
          status           Show active tokens, current kid, last rotation
          audit            Query the katagami_debug_bridge_audit log

        See 'shi debug-bridge <subcommand> --help' for options.
        """)
    }
}

// MARK: - token subcommand

/// `shi debug-bridge token --device <id> [--exp <duration>] [--scope <scopes>]`
/// Reads client_id/client_secret from Keychain.
/// POSTs to broker POST /oauth2/token.
/// Prints JWT to stdout (single use — caller stores in BridgeTokenCache actor).
struct DebugBridgeTokenSubcommand {
    static func run(args: [String]) async throws {
        var deviceID:  String? = nil
        var expSecs:   Int     = 86400   // default 24h
        var scopeStr:  String  = "read inspect snap"
        var i = 0
        while i < args.count {
            switch args[i] {
            case "--device":
                i += 1; guard i < args.count else { throw CLIError("--device requires a value") }
                deviceID = args[i]
            case "--exp":
                i += 1; guard i < args.count else { throw CLIError("--exp requires a value") }
                expSecs = try parseDuration(args[i])
            case "--scope":
                i += 1; guard i < args.count else { throw CLIError("--scope requires a value") }
                scopeStr = args[i]
            case "--help":
                print("Usage: shi debug-bridge token --device <id> [--exp <1h|4h|24h>] [--scope <scopes>]")
                return
            default:
                throw CLIError("Unknown flag: \(args[i])")
            }
            i += 1
        }
        let scope = DebugBridgeScope.parse(scopeStr)
        let (clientID, clientSecret) = try KeychainDebugBridgeCredentials.load(deviceID: deviceID)
        let brokerURL = try BrokerURLResolver.resolve()
        let token = try await DebugBridgeBrokerClient.issueToken(
            brokerURL: brokerURL,
            clientID: clientID,
            clientSecret: clientSecret,
            scope: scope,
            deviceID: deviceID,
            expSeconds: expSecs
        )
        // Print JWT to stdout. Caller (BridgeTokenCache) receives + caches.
        // NEVER written to file or env.
        print(token)
    }

    private static func parseDuration(_ s: String) throws -> Int {
        if s.hasSuffix("h"), let n = Int(s.dropLast()) { return n * 3600 }
        if s.hasSuffix("m"), let n = Int(s.dropLast()) { return n * 60  }
        if let n = Int(s) { return n }
        throw CLIError("Invalid duration '\(s)' — use e.g. 24h, 4h, 3600")
    }
}

// MARK: - revoke subcommand

/// `shi debug-bridge revoke <jti> | --device <id> | --all [--reason <text>]`
struct DebugBridgeRevokeSubcommand {
    static func run(args: [String]) async throws {
        var target: DebugBridgeRevokeRequest.Target? = nil
        var reason: String? = nil
        var i = 0
        while i < args.count {
            switch args[i] {
            case "--device":
                i += 1; guard i < args.count else { throw CLIError("--device requires a value") }
                target = .device(args[i])
            case "--all":
                target = .all
            case "--reason":
                i += 1; guard i < args.count else { throw CLIError("--reason requires a value") }
                reason = args[i]
            case "--help":
                print("Usage: shi debug-bridge revoke <jti> | --device <id> | --all [--reason <text>]")
                return
            default:
                if target == nil { target = .jti(args[i]) }
                else { throw CLIError("Unknown flag: \(args[i])") }
            }
            i += 1
        }
        guard let target else {
            throw CLIError("shi debug-bridge revoke: specify <jti>, --device <id>, or --all")
        }
        let sub = try KeychainDebugBridgeCredentials.currentSub()
        let req  = DebugBridgeRevokeRequest(target: target, revoked_by: "operator:\(sub)", reason: reason)
        let brokerURL = try BrokerURLResolver.resolve()
        try await DebugBridgeBrokerClient.revoke(brokerURL: brokerURL, request: req)
        switch target {
        case .jti(let j):    print("✓ Token \(j) revoked. NATS shikki.debug-bridge.revoked.\(j) published.")
        case .device(let d): print("✓ All tokens for device \(d) revoked. NATS mass-revoke published.")
        case .all:           print("✓ All active tokens revoked. NATS shikki.debug-bridge.revoked.all published.")
        }
    }
}

// MARK: - key-rotate subcommand

/// `shi debug-bridge key-rotate [--grace <duration>]`
struct DebugBridgeKeyRotateSubcommand {
    static func run(args: [String]) async throws {
        var graceSecs = 86400  // default 24h grace
        var i = 0
        while i < args.count {
            switch args[i] {
            case "--grace":
                i += 1; guard i < args.count else { throw CLIError("--grace requires a value") }
                graceSecs = try parseDuration(args[i])
            case "--help":
                print("Usage: shi debug-bridge key-rotate [--grace <24h|1h|0s>]")
                return
            default:
                throw CLIError("Unknown flag: \(args[i])")
            }
            i += 1
        }
        let brokerURL = try BrokerURLResolver.resolve()
        let resp = try await DebugBridgeBrokerClient.keyRotate(brokerURL: brokerURL, graceSeconds: graceSecs)
        print("""
        ✓ Key rotated.
          New kid : \(resp.kid_new)
          Old kid : \(resp.kid_old) (grace until \(resp.grace_ends_at))
          New tokens will be signed with \(resp.kid_new) immediately.
          Old-kid tokens remain valid during grace period.
        """)
    }

    private static func parseDuration(_ s: String) throws -> Int {
        if s.hasSuffix("h"), let n = Int(s.dropLast()) { return n * 3600 }
        if s.hasSuffix("s"), let n = Int(s.dropLast()) { return n }
        if s.hasSuffix("m"), let n = Int(s.dropLast()) { return n * 60 }
        if let n = Int(s) { return n }
        throw CLIError("Invalid duration '\(s)'")
    }
}

// MARK: - key-compromise subcommand

/// `shi debug-bridge key-compromise --kid <kid> | --all`
/// Emergency: no grace period. Immediate retirement + mass revoke + NATS revoke.all.
struct DebugBridgeKeyCompromiseSubcommand {
    static func run(args: [String]) async throws {
        var kid: String? = nil
        var all = false
        var i = 0
        while i < args.count {
            switch args[i] {
            case "--kid":
                i += 1; guard i < args.count else { throw CLIError("--kid requires a value") }
                kid = args[i]
            case "--all":
                all = true
            case "--help":
                print("Usage: shi debug-bridge key-compromise --kid <kid> | --all")
                return
            default:
                throw CLIError("Unknown flag: \(args[i])")
            }
            i += 1
        }
        guard kid != nil || all else {
            throw CLIError("shi debug-bridge key-compromise: specify --kid <kid> or --all")
        }
        let targetKid = all ? "__all__" : kid!
        let brokerURL = try BrokerURLResolver.resolve()
        let start = Date()
        let resp  = try await DebugBridgeBrokerClient.keyCompromise(brokerURL: brokerURL, kid: targetKid)
        let elapsed = Date().timeIntervalSince(start)
        print("""
        ✓ Key compromise emergency rotation complete.
          Compromised kid : \(resp.kid_compromised)
          New kid         : \(resp.kid_new)
          Tokens revoked  : \(resp.tokens_revoked)
          Completed at    : \(resp.completed_at)
          Elapsed         : \(String(format: "%.1f", elapsed))s
          NATS shikki.debug-bridge.revoked.all published — all bridges dropping connections.
        """)
        if elapsed > 300 {
            fputs("WARNING: elapsed \(elapsed)s exceeds TP-KDBR-03 5-minute gate\n", stderr)
        }
    }
}

// MARK: - register-device subcommand

/// `shi debug-bridge register-device --name <name>`
/// Generates client_id/client_secret, stores in Keychain, registers with broker.
struct DebugBridgeRegisterDeviceSubcommand {
    static func run(args: [String]) async throws {
        var name: String? = nil
        var i = 0
        while i < args.count {
            switch args[i] {
            case "--name":
                i += 1; guard i < args.count else { throw CLIError("--name requires a value") }
                name = args[i]
            case "--help":
                print("Usage: shi debug-bridge register-device --name <name>")
                return
            default:
                throw CLIError("Unknown flag: \(args[i])")
            }
            i += 1
        }
        guard let name else {
            throw CLIError("shi debug-bridge register-device: --name is required")
        }
        let brokerURL = try BrokerURLResolver.resolve()
        let (clientID, clientSecret, deviceID) = try await DebugBridgeBrokerClient.registerDevice(
            brokerURL: brokerURL,
            name: name
        )
        try KeychainDebugBridgeCredentials.store(
            clientID: clientID,
            clientSecret: clientSecret,
            deviceID: deviceID
        )
        // clientSecret printed ONCE to stdout for operator to verify.
        // NOT written to env, file, or DB. Keychain is authoritative.
        print("""
        ✓ Device '\(name)' registered.
          device_id  : \(deviceID)
          client_id  : \(clientID)
          client_secret has been stored in macOS Keychain.
          Run 'shi debug-bridge token' to issue a JWT.
        """)
    }
}

// MARK: - status subcommand

struct DebugBridgeStatusSubcommand {
    static func run(args: [String]) async throws {
        let brokerURL = try BrokerURLResolver.resolve()
        let status = try await DebugBridgeBrokerClient.status(brokerURL: brokerURL)
        print(status)
    }
}

// MARK: - audit subcommand

/// `shi debug-bridge audit [--since <timestamp>] [--device <id>] [--jti <jti>]
///                         [--kid <kid>] [--event-type <type>] [--format json|table]
///                         [--limit N] [--offset N]`
struct DebugBridgeAuditSubcommand {
    static func run(args: [String]) async throws {
        var since:     String? = nil
        var device:    String? = nil
        var jti:       String? = nil
        var kid:       String? = nil
        var eventType: String? = nil
        var format:    String  = "json"
        var limit:     Int     = 100
        var offset:    Int     = 0
        var i = 0
        while i < args.count {
            switch args[i] {
            case "--since":     i += 1; since     = args[i]
            case "--device":    i += 1; device    = args[i]
            case "--jti":       i += 1; jti       = args[i]
            case "--kid":       i += 1; kid       = args[i]
            case "--event-type":i += 1; eventType = args[i]
            case "--format":    i += 1; format    = args[i]
            case "--limit":     i += 1; limit     = Int(args[i]) ?? 100
            case "--offset":    i += 1; offset    = Int(args[i]) ?? 0
            case "--help":
                print("Usage: shi debug-bridge audit [--since <ts>] [--device <id>] [--jti <jti>] [--kid <kid>] [--event-type <type>] [--format json|table] [--limit N] [--offset N]")
                return
            default:
                throw CLIError("Unknown flag: \(args[i])")
            }
            i += 1
        }
        let brokerURL = try BrokerURLResolver.resolve()
        let result = try await DebugBridgeBrokerClient.queryAudit(
            brokerURL: brokerURL,
            since: since, device: device, jti: jti, kid: kid,
            eventType: eventType, format: format,
            limit: limit, offset: offset
        )
        print(result)
    }
}

// MARK: - Stubs (resolved at link time by ShiSecretsBrokerd)

/// Keychain credential helper — implementation in ShiSecretsKit/Admin/
enum KeychainDebugBridgeCredentials {
    static func load(deviceID: String?) throws -> (clientID: String, clientSecret: String) {
        fatalError("KeychainDebugBridgeCredentials.load — linked from AdminKeyCeremony")
    }
    static func store(clientID: String, clientSecret: String, deviceID: String) throws {
        fatalError("KeychainDebugBridgeCredentials.store — linked from AdminKeyCeremony")
    }
    static func currentSub() throws -> String {
        fatalError("KeychainDebugBridgeCredentials.currentSub — linked from AdminKeyCeremony")
    }
}

/// Broker URL resolver — reads from ~/.shikki/config.yml (never hardcoded).
enum BrokerURLResolver {
    static func resolve() throws -> URL {
        fatalError("BrokerURLResolver.resolve — linked from ShiSecretsKit/DI")
    }
}

/// Broker HTTP client stub — implementation in ShiSecretsKit/Broker/
enum DebugBridgeBrokerClient {
    static func issueToken(brokerURL: URL, clientID: String, clientSecret: String,
                           scope: DebugBridgeScope, deviceID: String?, expSeconds: Int) async throws -> String {
        fatalError("DebugBridgeBrokerClient.issueToken")
    }
    static func revoke(brokerURL: URL, request: DebugBridgeRevokeRequest) async throws { fatalError() }
    static func keyRotate(brokerURL: URL, graceSeconds: Int) async throws -> DebugBridgeKeyRotateResponse { fatalError() }
    static func keyCompromise(brokerURL: URL, kid: String) async throws -> DebugBridgeKeyCompromiseResponse { fatalError() }
    static func registerDevice(brokerURL: URL, name: String) async throws -> (clientID: String, clientSecret: String, deviceID: String) { fatalError() }
    static func status(brokerURL: URL) async throws -> String { fatalError() }
    static func queryAudit(brokerURL: URL, since: String?, device: String?, jti: String?,
                           kid: String?, eventType: String?, format: String,
                           limit: Int, offset: Int) async throws -> String { fatalError() }
}

// MARK: - CLIError

struct CLIError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}
