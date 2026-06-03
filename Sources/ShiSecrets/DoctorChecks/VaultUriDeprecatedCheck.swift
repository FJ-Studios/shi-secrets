// VaultUriDeprecatedCheck — doctor check for legacy `vault://` URIs.
//
// Greps Sources/ + features/ + plugins/ for `vault://` patterns.
// Returns CRIT with migration hint if any are found.
// BR-SSEC-15: doctor check `shi doctor --check vault-uri-deprecated`.
// TP-SSEC-17: greps for vault:// in Sources/ + features/ + plugins/ → CRIT with hint.
//
// W6 of features/shi-secrets-uri-scheme-and-plugin-extraction-2026-05-31.md.

import Foundation
import ShikkiPluginAPI

/// Detects legacy `vault://` URIs that should be migrated to `shi-secret://`.
///
/// Per [[secret-refs-via-shi-secrets-broker-not-vault-uri]]: `vault://` named the
/// backend (Vaultwarden), not the scheme. Canonical scheme is `shi-secret://`.
public struct VaultUriDeprecatedCheck: PluginDoctorRegistrar {

    public static let checkName = "vault-uri-deprecated"
    public static let severity = DoctorSeverity.crit

    public static func run() async throws -> [DoctorFinding] {
        let workspaceRoot = findWorkspaceRoot()
        let searchPaths: [String] = [
            "\(workspaceRoot)/Sources",
            "\(workspaceRoot)/features",
            "\(workspaceRoot)/plugins",
            "\(workspaceRoot)/packages",
            "\(workspaceRoot)/apps",
        ]

        var findings: [DoctorFinding] = []

        for base in searchPaths {
            guard FileManager.default.fileExists(atPath: base) else { continue }
            let hits = try grep(pattern: "vault://", inDirectory: base,
                                extensions: [".swift", ".md", ".toml", ".yaml", ".yml"])
            for hit in hits {
                findings.append(DoctorFinding(
                    file: hit.file,
                    line: hit.line,
                    message: "Legacy vault:// URI found at \(hit.file):\(hit.line) — "
                           + "migrate to shi-secret://<namespace>/<key> per "
                           + "[[secret-refs-via-shi-secrets-broker-not-vault-uri]].",
                    severity: .crit
                ))
            }
        }
        return findings
    }

    // MARK: - Private helpers

    private struct GrepHit {
        let file: String
        let line: Int
    }

    private static func grep(
        pattern: String,
        inDirectory dir: String,
        extensions: [String]
    ) throws -> [GrepHit] {
        var hits: [GrepHit] = []
        let enumerator = FileManager.default.enumerator(
            at: URL(fileURLWithPath: dir),
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles, .skipsPackageDescendants]
        )
        while let item = enumerator?.nextObject() as? URL {
            guard extensions.contains(item.pathExtension.isEmpty ? item.lastPathComponent : ".\(item.pathExtension)") else { continue }
            guard let text = try? String(contentsOf: item, encoding: .utf8) else { continue }
            let lines = text.components(separatedBy: "\n")
            for (idx, line) in lines.enumerated() {
                if line.contains(pattern) {
                    hits.append(GrepHit(file: item.path, line: idx + 1))
                }
            }
        }
        return hits
    }

    private static func findWorkspaceRoot() -> String {
        // Walk up from process cwd looking for Package.swift
        var url = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        for _ in 0..<10 {
            if FileManager.default.fileExists(atPath: url.appendingPathComponent("Package.swift").path) {
                return url.path
            }
            url = url.deletingLastPathComponent()
        }
        return FileManager.default.currentDirectoryPath
    }
}
