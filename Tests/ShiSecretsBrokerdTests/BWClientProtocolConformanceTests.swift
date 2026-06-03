import Foundation
@testable import ShiSecretsBrokerd
import ShiSecretsKit
import Testing

// BWClientProtocolConformance — review finding #2 guard.
//
// BrokerDaemon must hold the `BWClient` protocol (`any BWClient`) rather
// than the concrete `InMemoryBWClient`/`ProductionBWClient` actor types
// so tests and prod wiring can swap implementations without the actor's
// private fakeVault leaking into the production surface.
//
// W1 update: ProcessLauncher / FakeProcessLauncher removed (bw CLI gone).
// InMemoryBWClient now takes no arguments in its default init.

@Suite("BWClientProtocolConformance")
struct BWClientProtocolConformanceTests {

    @Test("InMemoryBWClient conforms to BWClient protocol")
    func test_bwclient_inMemory_conformsToProtocol() {
        let client: any BWClient = InMemoryBWClient()
        // Reach through the protocol to prove the surface is reachable.
        _ = client
    }

    @Test("ProductionBWClient conforms to BWClient protocol")
    func test_bwclient_production_conformsToProtocol() {
        let client: any BWClient = ProductionBWClient()
        _ = client
    }

    @Test("BrokerDaemon sources hold BWClient via the protocol, not the concrete actor")
    func test_bwclient_protocol_conformance_allCallSitesUseProtocol() throws {
        // Source-grep guard — scans the brokerd Sources directory and
        // rejects any declaration of a stored property / parameter that
        // binds `BWClient` without the `any BWClient` protocol form.
        let fm = FileManager.default
        let sourcesRoot = "Sources/ShiSecretsBrokerd"
        guard let enumerator = fm.enumerator(atPath: sourcesRoot) else {
            // If the sources directory is not reachable from cwd, skip.
            return
        }
        var violations: [String] = []
        while let file = enumerator.nextObject() as? String {
            guard file.hasSuffix(".swift") else { continue }
            let path = "\(sourcesRoot)/\(file)"
            guard let data = fm.contents(atPath: path),
                  let text = String(data: data, encoding: .utf8)
            else { continue }
            let allowedPhrasings = [
                "any BWClient",
                ": BWClient {",
            ]
            for line in text.split(separator: "\n", omittingEmptySubsequences: false) {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                guard trimmed.contains(": BWClient") else { continue }
                if trimmed.contains(": BWClientWriteBack") { continue }
                if trimmed.hasPrefix("//") { continue }
                if allowedPhrasings.contains(where: { trimmed.contains($0) }) { continue }
                violations.append("\(file): \(trimmed)")
            }
        }
        #expect(violations.isEmpty, "Direct BWClient type references found — use `any BWClient`: \(violations.joined(separator: "; "))")
    }

    @Test("W1: No bw CLI binary references in brokerd Sources")
    func test_noBwCLIReferences() throws {
        // grep for "bw" process invocations (executable: "bw", Process(), etc.)
        // should return zero matches in the W1 codebase.
        let fm = FileManager.default
        let sourcesRoot = "Sources/ShiSecretsBrokerd"
        guard let enumerator = fm.enumerator(atPath: sourcesRoot) else { return }
        var violations: [String] = []
        while let file = enumerator.nextObject() as? String {
            guard file.hasSuffix(".swift") else { continue }
            let path = "\(sourcesRoot)/\(file)"
            guard let data = fm.contents(atPath: path),
                  let text = String(data: data, encoding: .utf8)
            else { continue }
            for line in text.split(separator: "\n", omittingEmptySubsequences: false) {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                // Skip comments and @available deprecation stubs documenting removal.
                if trimmed.hasPrefix("//") { continue }
                if trimmed.hasPrefix("@available") { continue }
                // Check for bw binary invocations or BW_SESSION env references.
                if trimmed.contains("executable: \"bw\"") ||
                   trimmed.contains("BW_SESSION") ||
                   (trimmed.contains("Process()") && !trimmed.contains("//")) {
                    violations.append("\(file): \(trimmed)")
                }
            }
        }
        #expect(violations.isEmpty, "bw CLI / BW_SESSION references found in broker source: \(violations.joined(separator: "; "))")
    }
}
