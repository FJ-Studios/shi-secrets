import Foundation
import ShiSecretsKit
import ShiSecretsClient

// TokenCommand — `shi token …` subcommand surface (T61 — BR-F-03,
// BR-F-04 + item #9 BR-F-08…BR-F-11).
//
// Subcommands:
//   revoke <jti>                              — revoke one token
//   revoke --all-bots                         — interactive dry-run + y/N + broker revoke
//   revoke --all-bots --force                 — DEPRECATED (item #9)
//   revoke --all-bots --signed-envelope <p|-> — passkey-signed admin gate
//
// Item #9 (BR-F-08…BR-F-11): the legacy `--force` filesystem-only
// gate is retired. Admin actions now require a `SignedAdminAction`
// envelope produced by the operator's Mac Secure Enclave via
// `shikki-admin-sign`; the broker verifies the Ed25519 signature
// against the pinned admin pubkey + domain-separates it from the
// manifest class.
//
// Flow for `--all-bots` (non-force):
//   1. Ask broker for a blast-radius summary of every bot token
//   2. Render "would revoke N bot tokens, preserve M passkey-path tokens"
//   3. Prompt `y/N` via injected `PromptReader`
//   4. On confirm: delegate `revokeAllBots` over socket
//
// Flow for `--all-bots --signed-envelope <path|->`:
//   1. Read the `SignedAdminAction` JSON from file or stdin
//   2. Delegate to `BrokerClient.revokeAllBotsSigned(_:)` — the broker
//      enforces the verification; the CLI never touches the signature

public protocol PromptReader: Sendable {
    /// Read one line of user input. Returns nil on EOF.
    func readLine() async -> String?
}

public actor ScriptedPromptReader: PromptReader {
    private var responses: [String]
    public init(responses: [String]) { self.responses = responses }
    public func readLine() async -> String? {
        responses.isEmpty ? nil : responses.removeFirst()
    }
}

public protocol SeamsRecorder: Sendable {
    /// Record an operator-driven seam (e.g. `--force` incident bypass).
    func recordIncidentBypass(secret: String, notes: String) async throws
}

public actor InMemorySeamsRecorder: SeamsRecorder {
    public private(set) var events: [(secret: String, notes: String)] = []
    public init() {}
    public func recordIncidentBypass(secret: String, notes: String) async throws {
        events.append((secret, notes))
    }
    public func snapshot() -> [(secret: String, notes: String)] { events }
}

public enum TokenSubcommand: String, Sendable, Equatable, CaseIterable {
    case revoke
}

/// Item #9 — CLI error surface specific to the admin-gated revoke
/// path. Distinct from `SecretCommandError` so callers can
/// `case`-match the exact failure without string-matching.
public enum TokenCommandError: Swift.Error, Sendable, Equatable {
    /// `--force` was passed without `--signed-envelope` — the legacy
    /// filesystem-only gate is retired.
    case adminSignatureRequired
    /// `--signed-envelope <path>` was passed but the file could not be
    /// read.
    case signedEnvelopeUnreadable(path: String)
    /// The envelope bytes could not be decoded as `SignedAdminAction`.
    case signedEnvelopeMalformed(detail: String)
}

public struct TokenCommand: Sendable {
    public let client: any BrokerClient
    public let prompt: any PromptReader
    public let seams: any SeamsRecorder

    public init(
        client: any BrokerClient,
        prompt: any PromptReader,
        seams: any SeamsRecorder
    ) {
        self.client = client
        self.prompt = prompt
        self.seams = seams
    }

    /// Dispatch a `shi token revoke` invocation. `args` is the argv tail
    /// after `token revoke`: e.g. `["--all-bots"]`,
    /// `["--all-bots", "--force"]` (retired in item #9 — now an error),
    /// `["--all-bots", "--signed-envelope", "path"]`, or `["01JC…K7P"]`.
    ///
    /// `envelopeReader` closure lets tests inject the raw envelope
    /// bytes; production wiring reads from `path` or stdin. Kept as a
    /// closure (not a protocol) so the CLI target stays free of a new
    /// I/O protocol for one call site.
    public func runRevoke(
        args: [String],
        envelopeReader: @Sendable (String) async throws -> Data = Self.readEnvelopeBytes
    ) async throws -> CLIOutput {
        var out = CLIOutput()
        let flags = Set(args.filter { $0.hasPrefix("--") })

        if flags.contains("--all-bots") {
            return try await runRevokeAllBots(args: args, flags: flags, envelopeReader: envelopeReader, out: &out)
        }

        // Single-jti revoke.
        let positional = args.filter { !$0.hasPrefix("--") }
        guard let jti = positional.first else {
            throw SecretCommandError.missingArgument(name: "jti")
        }
        try await client.revoke(jti: jti)
        out.outln("revoked \(jti)")
        return out
    }

    /// Split out for clarity — item #9 adds two new branches to the
    /// `--all-bots` dispatcher (signed-envelope + retired --force).
    private func runRevokeAllBots(
        args: [String],
        flags: Set<String>,
        envelopeReader: @Sendable (String) async throws -> Data,
        out: inout CLIOutput
    ) async throws -> CLIOutput {
        // Item #9 — `--force` alone is retired. A caller passing
        // `--force` without `--signed-envelope` gets the new error
        // surface pointing at the `shikki-admin-sign` pipeline.
        let envelopePath = valueForFlag("--signed-envelope", in: args)
        let hasForce = flags.contains("--force")
        if hasForce && envelopePath == nil {
            out.errln("Admin actions require a signed envelope. Run: `shikki-admin-sign revoke-all-bots | shi token revoke --all-bots --signed-envelope -`")
            throw TokenCommandError.adminSignatureRequired
        }

        // Item #9 — signed-envelope path. The broker verifies the
        // envelope; the CLI's job is to (a) read the bytes, (b)
        // decode, (c) delegate. No crypto on the CLI side.
        if let path = envelopePath {
            let bytes: Data
            do {
                bytes = try await envelopeReader(path)
            } catch {
                throw TokenCommandError.signedEnvelopeUnreadable(path: path)
            }
            let signed: SignedAdminAction
            do {
                let decoder = JSONDecoder()
                decoder.dateDecodingStrategy = .iso8601
                signed = try decoder.decode(SignedAdminAction.self, from: bytes)
            } catch {
                throw TokenCommandError.signedEnvelopeMalformed(detail: String(describing: error))
            }
            let applied = try await client.revokeAllBotsSigned(signed)
            out.outln("revoked \(applied.revokedCount) bot tokens · preserved \(applied.passkeyPreservedCount) passkey-path tokens (signed by \(signed.envelope.actor))")
            return out
        }

        // Interactive path (unchanged from Wave 5).
        let dry = try await client.revokeAllBots(dryRun: true, force: false)
        out.outln("dry-run: would revoke \(dry.revokedCount) bot tokens")
        out.outln("         preserve \(dry.passkeyPreservedCount) passkey-path tokens")
        out.out("proceed? [y/N]: ")
        let answer = (await prompt.readLine() ?? "").lowercased()
        guard answer == "y" || answer == "yes" else {
            out.outln("aborted.")
            return out
        }
        let applied = try await client.revokeAllBots(dryRun: false, force: false)
        out.outln("revoked \(applied.revokedCount) bot tokens · preserved \(applied.passkeyPreservedCount) passkey-path tokens")
        return out
    }

    /// Look up a `--flag value` arg pair in `args`. Returns `nil`
    /// when the flag is absent. `--flag=value` form is also
    /// supported.
    private func valueForFlag(_ flag: String, in args: [String]) -> String? {
        for (idx, arg) in args.enumerated() {
            if arg == flag, idx + 1 < args.count {
                return args[idx + 1]
            }
            if arg.hasPrefix(flag + "=") {
                return String(arg.dropFirst(flag.count + 1))
            }
        }
        return nil
    }

    /// Default envelope reader — `-` reads stdin, any other path
    /// reads the file. Production entrypoint; tests inject their
    /// own closure returning in-memory bytes.
    public static let readEnvelopeBytes: @Sendable (String) async throws -> Data = { path in
        if path == "-" {
            return FileHandle.standardInput.readDataToEndOfFile()
        }
        return try Data(contentsOf: URL(fileURLWithPath: path))
    }
}

public enum TokenCommandRegistry {
    public static var subcommandNames: [String] {
        TokenSubcommand.allCases.map(\.rawValue).sorted()
    }
}
