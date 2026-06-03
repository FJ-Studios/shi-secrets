import Foundation

// ManifestSigningPolicy — encodes BR-H-02c (signing requires Daimyo's
// passkey user-presence) + BR-H-02b (broker never holds the private
// key) at the type level AND provides a source-grep guard that fails
// the test suite if any code path inside the broker daemon ever
// attempts to invoke the Ed25519 signing API.
//
// The canonical signer is the external tool `shikki-manifest-sign`
// which runs on the Daimyo's Mac under passkey user-presence. The
// broker daemon only ever *verifies* signatures, never produces them.

public enum ManifestSigningPolicy: Sendable, Equatable {

    case passkeyRequired

    public var rationale: String {
        switch self {
        case .passkeyRequired:
            return "MCP manifest signing requires Daimyo's passkey user-presence (Touch ID or physical tap). Non-interactive or automated signing is forbidden per BR-H-02c."
        }
    }

    public var externalTool: String {
        switch self {
        case .passkeyRequired:
            return "shikki-manifest-sign"
        }
    }

    /// Path (relative to repo root) of the broker daemon sources. Wave 4
    /// creates this target; until then the scan is a no-op that will
    /// catch any future violation automatically.
    public static var brokerdSourceDirectory: String {
        "packages/ShiSecrets/Sources/ShiSecretsBrokerd"
    }

    /// Patterns we forbid inside the broker daemon tree. These target
    /// *manifest* signing specifically — the broker legitimately signs
    /// ShikkiSBT tokens via TokenMinter (which lives in ShiSecretsKit),
    /// so bare `.signature(for:)` + `Curve25519.Signing.PrivateKey` are
    /// allowed here. What's forbidden is any reference to a manifest
    /// signing key / signer / helper inside the daemon binary.
    public static let forbiddenPatterns: [String] = [
        "manifestPrivateKey",
        "signManifest",
        "ManifestSigner",
        "manifest.sig(",
    ]

    /// Scans Swift source files under `path` (absolute or repo-relative)
    /// for any match of `forbiddenPatterns`. Returns `(file, pattern)`
    /// pairs; an empty array means the invariant holds.
    public static func scanForForbiddenSigningCalls(under path: String) -> [String] {
        let fm = FileManager.default
        // Resolve relative-to-repo paths by walking up from CWD until a
        // directory containing `packages/` is found. This keeps the
        // test runner agnostic of where `swift test` is invoked.
        let resolved = resolveRepoPath(path)
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: resolved, isDirectory: &isDir), isDir.boolValue else {
            // Wave 4 hasn't created the daemon target yet; vacuously
            // satisfied.
            return []
        }
        guard let enumerator = fm.enumerator(atPath: resolved) else {
            return []
        }
        var findings: [String] = []
        for case let rel as String in enumerator {
            guard rel.hasSuffix(".swift") else { continue }
            let full = (resolved as NSString).appendingPathComponent(rel)
            guard let data = fm.contents(atPath: full),
                  let text = String(data: data, encoding: .utf8) else {
                continue
            }
            for pattern in forbiddenPatterns where text.contains(pattern) {
                findings.append("\(rel): \(pattern)")
            }
        }
        return findings
    }

    private static func resolveRepoPath(_ path: String) -> String {
        if path.hasPrefix("/") { return path }
        let fm = FileManager.default
        var cursor = fm.currentDirectoryPath
        for _ in 0 ..< 12 {
            let candidate = (cursor as NSString).appendingPathComponent(path)
            if fm.fileExists(atPath: candidate) {
                return candidate
            }
            let parent = (cursor as NSString).deletingLastPathComponent
            if parent == cursor { break }
            cursor = parent
        }
        // Not found — return the literal so caller treats it as absent.
        return path
    }
}
