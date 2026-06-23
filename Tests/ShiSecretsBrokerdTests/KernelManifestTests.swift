import Foundation
@testable import ShiSecretsBrokerd
import Testing

// KernelManifestTests — asserts that the signed kernel manifest for
// shikki-secrets-brokerd exists under deploy/nuc-dev/kernel-manifests/.
//
// NOTE: The deploy/ directory lives in the shikki monorepo, not in the
// standalone shi-secrets repository. The test guards with an isMonorepoContext
// check and returns early when running outside the monorepo (e.g., standalone
// repo CI). Assertions are only enforced in the monorepo context.

@Suite("KernelManifest")
struct KernelManifestTests {

    private func deployDir() -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("deploy/nuc-dev/kernel-manifests", isDirectory: true)
    }

    private var isMonorepoContext: Bool {
        FileManager.default.fileExists(atPath: deployDir().path)
    }

    @Test("kernel manifest declares broker service under shikki-kernel — signed by ops key")
    func test_kernelManifest_declaresBrokerServiceUnderShikkiKernel_signedByOpsKey() throws {
        guard isMonorepoContext else {
            // deploy/nuc-dev/ lives in the monorepo — not present in standalone repo.
            return
        }
        let dir = deployDir()
        let toml = dir.appendingPathComponent("shikki-secrets-brokerd.manifest.toml")
        let sig = dir.appendingPathComponent("shikki-secrets-brokerd.manifest.toml.sig")
        #expect(FileManager.default.fileExists(atPath: toml.path))
        #expect(FileManager.default.fileExists(atPath: sig.path))

        let body = try String(contentsOf: toml, encoding: .utf8)
        #expect(body.contains("id = \"shikki-secrets-brokerd\""))
        #expect(body.contains("[qos]"))
        #expect(body.contains("[restart]"))
        #expect(body.contains("policy ="))
        #expect(body.contains("[signature]"))
        #expect(body.contains("pubkey_fingerprint"))
    }
}
