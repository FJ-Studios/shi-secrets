// SecretsToEnvCommand — `shi secrets-to-env --secret KEY=<uri> ... -- <cmd>`
//
// Pre-resolves N URIs to env vars, then execve()s child process.
// Parent process is REPLACED by child (execve, not fork).
// Per BR-SSEC-12: NEVER writes .env file or /etc/<svc>/secrets.
// TP-SSEC-11: pre-resolves N URIs, execve child with env, parent exits.
//
// W3+W4 of features/shi-secrets-uri-scheme-and-plugin-extraction-2026-05-31.md.

import Foundation
import ShiSecretsKit
#if canImport(Darwin)
import Darwin
#endif

/// `shi secrets-to-env --secret KEY=<uri> [--secret KEY2=<uri2>] -- <cmd>`
///
/// Resolves each secret URI and injects as env vars, then execve(2)s <cmd>.
/// The parent shell is replaced by <cmd> — secrets never persist beyond
/// the child process lifetime (BR-SSEC-12).
public struct SecretsToEnvCommand {

    /// Mapping of ENV_KEY → shi-secret:// URI string.
    public let secrets: [(envKey: String, uri: String)]
    /// Command + arguments to exec.
    public let command: [String]

    public init(secrets: [(envKey: String, uri: String)], command: [String]) {
        self.secrets = secrets
        self.command = command
    }

    public func run(brokerSocket: String) async throws -> Int32 {
        guard !command.isEmpty else {
            fputs("ERROR: no command specified after --\n", stderr)
            return 1
        }

        var envPairs: [(key: String, value: String)] = []

        // NEW-M3 / BR-G-01: emit an audit-warn row before resolving each secret in
        // plaintext. `to-env` always uses the plaintext path (execve injection requires
        // the raw value) — unlike `secrets get` which defaults to an ephemeral JTI.
        // The warn is emitted to stderr so it is captured by process supervisors
        // (launchd / systemd) and is NOT visible in the child's stdin/stdout.
        // One warn line per URI is emitted so the audit trail maps 1:1 to resolved URIs.
        fputs("WARNING: shi secrets to-env resolves plaintext. Each URI resolution is audit-logged (BR-G-01).\n", stderr)

        // Pre-resolve all URIs before execve.
        let client = ShiSecretsAPIClient(socket: brokerSocket)
        for (envKey, rawURI) in secrets {
            let parsedURI: ShiSecretURI
            do {
                parsedURI = try ShiSecretURI.parse(rawURI)
            } catch {
                fputs("ERROR: invalid URI for \(envKey): \(error.localizedDescription)\n", stderr)
                return 1
            }
            // NEW-M3: per-URI audit-warn so callers can correlate warn lines to env keys.
            fputs("AUDIT-WARN: plaintext resolve for env key \(envKey) (\(rawURI))\n", stderr)
            do {
                let value = try await client.resolveValue(uri: parsedURI)
                envPairs.append((key: envKey, value: value))
            } catch {
                fputs("ERROR: could not resolve \(rawURI): \(error.localizedDescription)\n", stderr)
                return 1
            }
        }

        // Build env array for execve: inherit + inject resolved secrets.
        var env = ProcessInfo.processInfo.environment
        for (key, value) in envPairs {
            env[key] = value
        }

        // Resolve full path to executable.
        let execPath: String
        let cmdName = command[0]
        if cmdName.hasPrefix("/") {
            execPath = cmdName
        } else {
            // Search PATH for the binary.
            let paths = (env["PATH"] ?? "/usr/local/bin:/usr/bin:/bin").split(separator: ":").map(String.init)
            guard let found = paths.first(where: { path in
                FileManager.default.isExecutableFile(atPath: "\(path)/\(cmdName)")
            }) else {
                fputs("ERROR: command not found in PATH: \(cmdName)\n", stderr)
                return 127
            }
            execPath = "\(found)/\(cmdName)"
        }

        // Build argv and envp as C arrays.
        let argv: [UnsafeMutablePointer<CChar>?] = command.map { strdup($0) } + [nil]
        let envp: [UnsafeMutablePointer<CChar>?] = env.map { strdup("\($0.key)=\($0.value)") } + [nil]

        defer {
            // Free is only reached if execve fails.
            argv.forEach { if let p = $0 { free(p) } }
            envp.forEach { if let p = $0 { free(p) } }
        }

        // execve replaces this process — secrets never written to disk.
        let rc = execve(execPath, argv, envp)
        // Only reached on failure.
        fputs("ERROR: execve(\(execPath)) failed: \(String(cString: strerror(errno)))\n", stderr)
        return Int32(rc)
    }
}
