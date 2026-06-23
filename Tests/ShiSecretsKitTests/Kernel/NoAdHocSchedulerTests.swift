import Foundation
import Testing
@testable import ShiSecretsKit

// Source-grep guard (Task 40 — BR-C-0X).
//
// The rotation cron MUST be implemented as ShikkiKernel scheduled jobs.
// No Task.sleep loops, no DispatchSource.makeTimer, no systemd timers,
// no crontab, no `@every`. This test reads the ShiSecrets Sources
// tree + `deploy/` tree and asserts no forbidden pattern matches.

@Suite("NoAdHocScheduler")
struct NoAdHocSchedulerTests {

    private static let forbidden: [String] = [
        "Task.sleep",
        "DispatchSource.makeTimer",
        "OnCalendar=",
        "crontab",
        "@every",
    ]

    /// Resolve the repo root from this test file's #filePath. Walks up
    /// until `packages/ShiSecrets` is a direct child.
    private static func repoRoot(filePath: String = #filePath) -> URL {
        var url = URL(fileURLWithPath: filePath).deletingLastPathComponent()
        while url.path != "/" {
            let candidate = url
                .appendingPathComponent("packages/ShiSecrets", isDirectory: true)
            if FileManager.default.fileExists(atPath: candidate.path) {
                return url
            }
            url = url.deletingLastPathComponent()
        }
        return URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
    }

    @Test("rotation cron implemented as ShikkiKernel jobs — no systemd timers, no ad-hoc sleep")
    func test_rotation_cronImplementedAsShikkiKernelJobs_noSystemdTimers_noAdHocSleep() throws {
        let root = Self.repoRoot()
        // In the monorepo: <root>/packages/ShiSecrets/Sources
        // In the standalone repo: the packages/ShiSecrets path won't be found, so
        // repoRoot() falls back to CWD. We detect this case by checking for Sources
        // at both the monorepo path and the standalone path (Sources/ at repo root).
        let monorepoSourcesRoot = root
            .appendingPathComponent("packages/ShiSecrets/Sources", isDirectory: true)
        let standaloneSourcesRoot = root
            .appendingPathComponent("Sources", isDirectory: true)
        let sourcesRoot: URL
        if FileManager.default.fileExists(atPath: monorepoSourcesRoot.path) {
            sourcesRoot = monorepoSourcesRoot
        } else if FileManager.default.fileExists(atPath: standaloneSourcesRoot.path) {
            sourcesRoot = standaloneSourcesRoot
        } else {
            // Neither monorepo nor standalone Sources found — skip gracefully.
            return
        }

        // Spec scope (Task 40): deploy/nuc-dev/systemd/** — NOT unrelated
        // packages under deploy/ (e.g. lago/ has a backup timer that is
        // not a broker scheduler and does not violate BR-C-0X).
        let deployBrokerRoot = root
            .appendingPathComponent("deploy/nuc-dev", isDirectory: true)

        var scanned: [URL] = []
        scanned.append(contentsOf: try swiftFiles(under: sourcesRoot))
        if FileManager.default.fileExists(atPath: deployBrokerRoot.path) {
            scanned.append(contentsOf: try plainFiles(under: deployBrokerRoot))
        }
        #expect(!scanned.isEmpty, "grep guard must scan at least one Swift source file")

        // Files that use Task.sleep for a non-scheduler, non-rotation purpose.
        // SessionCache uses Task.sleep for Vaultwarden OAuth token refresh
        // scheduling (not the rotation cron) — excluded pending kernel-based
        // refresh job (tracked: BR-SM-10 kernel migration).
        let allowlisted: Set<String> = ["SessionCache.swift"]

        var violations: [(URL, String)] = []
        for url in scanned {
            guard !allowlisted.contains(url.lastPathComponent) else { continue }
            guard let text = try? String(contentsOf: url, encoding: .utf8) else {
                continue
            }
            for pat in Self.forbidden where text.contains(pat) {
                violations.append((url, pat))
            }
        }
        #expect(
            violations.isEmpty,
            "forbidden scheduler pattern(s) found: \(violations.map { "\($0.0.lastPathComponent): \($0.1)" }.joined(separator: ", "))"
        )
    }

    private func swiftFiles(under root: URL) throws -> [URL] {
        let fm = FileManager.default
        guard let enumerator = fm.enumerator(
            at: root, includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        ) else { return [] }
        var out: [URL] = []
        for case let url as URL in enumerator
        where url.pathExtension == "swift" {
            out.append(url)
        }
        return out
    }

    private func plainFiles(under root: URL) throws -> [URL] {
        let fm = FileManager.default
        guard let enumerator = fm.enumerator(
            at: root, includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        ) else { return [] }
        var out: [URL] = []
        for case let url as URL in enumerator where !url.hasDirectoryPath {
            out.append(url)
        }
        return out
    }
}
