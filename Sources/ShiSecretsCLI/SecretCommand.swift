import Foundation
import ShiSecretsKit
import ShiSecretsClient

// SecretCommand — the `shi secret …` subcommand surface (T57 + T58).
//
// Subcommands:
//   get <name>       — fetch plaintext + render inline footer on stderr
//   fetch <name>     — alias for `get` (operator muscle-memory parity with gh/bw)
//   list             — list vault entries the caller is entitled to
//   set  <name> <v>  — write a new vault entry (CLI-side validation only;
//                      broker rejects on scope mismatch)
//   rotate <name>    — force-rotate one entry (two-channel confirm)
//   revoke <jti>     — revoke a single token by jti
//
// BR coverage:
//   BR-A-06  get's footer uses `dies in`; NEVER `expires_at`
//   BR-B-03  rotate delegates over the broker socket + two-channel confirm
//
// Wave 5 pass: this is *plumbing* — every subcommand delegates into a
// `BrokerClient` protocol. The production client (Unix socket JSON-RPC)
// lives in the `ShiSecretsBrokerd` target and is injected at main()
// time. Tests supply an in-process recording client so the CLI layer can
// be unit-tested end-to-end without a live broker.

// BrokerClient protocol + RotationResult / RevokeAllBotsResult /
// BlastRadiusReport moved to ShiSecretsClient target (Phase 0.2,
// BR-G-03 of features/shikkisecrets-broker-completion.md). Imported via
// `import ShiSecretsClient` above — types stay source-compatible for
// existing consumers.

/// Transcript the CLI writes during a single run. Useful for tests +
/// AppLog wiring.
public struct CLIOutput: Sendable, Equatable {
    public var stdout: String = ""
    public var stderr: String = ""
    public init() {}

    public mutating func out(_ s: String) { stdout += s }
    public mutating func err(_ s: String) { stderr += s }
    public mutating func outln(_ s: String) { stdout += s + "\n" }
    public mutating func errln(_ s: String) { stderr += s + "\n" }
}

public enum SecretCommandError: Swift.Error, Sendable, Equatable {
    case missingArgument(name: String)
    case unknownSubcommand(String)
    case brokerDenied(reason: String)
}

public enum SecretSubcommand: String, Sendable, Equatable, CaseIterable {
    case get
    /// Alias for `get` — operator muscle-memory parity with `gh secret fetch` + `bw fetch`.
    case fetch
    case list
    case set
    case rotate
    case revoke
}

public struct SecretCommand: Sendable {

    public let client: any BrokerClient
    /// Context provider for the footer — the CLI assembles the context
    /// from whatever data the broker returns + local timestamps. Tests
    /// inject a deterministic provider.
    public let footerContextProvider: @Sendable (_ name: String) async -> InlineFooterContext?

    public init(
        client: any BrokerClient,
        footerContextProvider: @escaping @Sendable (_ name: String) async -> InlineFooterContext?
    ) {
        self.client = client
        self.footerContextProvider = footerContextProvider
    }

    /// Dispatch. Returns the full transcript so tests can assert both
    /// stdout + stderr shape.
    public func run(subcommand: SecretSubcommand, args: [String]) async throws -> CLIOutput {
        var out = CLIOutput()
        switch subcommand {
        case .get, .fetch:
            // `.fetch` is a transparent alias for `.get` — identical behaviour.
            guard let name = args.first else {
                throw SecretCommandError.missingArgument(name: "name")
            }
            let plaintext = try await client.get(name: name)
            out.outln(plaintext)
            if let ctx = await footerContextProvider(name) {
                out.errln(InlineFooter.render(ctx))
            }
        case .list:
            let filter = args.first
            let entries = try await client.list(filter: filter)
            for e in entries {
                out.outln("\(e.name)\t\(e.scope)\t\(e.tier.rawValue)\t\(e.usageState.rawValue)")
            }
        case .set:
            guard args.count >= 2 else {
                throw SecretCommandError.missingArgument(name: "value")
            }
            try await client.set(name: args[0], value: args[1])
            out.outln("set \(args[0]) OK")
        case .rotate:
            guard let name = args.first else {
                throw SecretCommandError.missingArgument(name: "name")
            }
            let result = try await client.rotate(name: name)
            let confirm = TwoChannelConfirm.renderTerminalPair(for: result, timeZone: "CET")
            out.outln(confirm)
        case .revoke:
            guard let jti = args.first else {
                throw SecretCommandError.missingArgument(name: "jti")
            }
            try await client.revoke(jti: jti)
            out.outln("revoked \(jti)")
        }
        return out
    }
}

/// Convenience — list the five subcommand names so `apps/shi` registry
/// tests can assert the plumbing is complete.
public enum SecretCommandRegistry {
    public static var subcommandNames: [String] {
        SecretSubcommand.allCases.map(\.rawValue).sorted()
    }
}
