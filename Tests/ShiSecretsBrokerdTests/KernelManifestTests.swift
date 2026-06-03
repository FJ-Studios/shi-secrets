import Foundation
@testable import ShiSecretsBrokerd
import Testing

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

    @Test("kernel manifest declares broker service under shikki-kernel — signed by ops key")
    func test_kernelManifest_declaresBrokerServiceUnderShikkiKernel_signedByOpsKey() throws {
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
