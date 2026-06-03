import Foundation
@testable import ShiSecretsDrivers
import ShiSecretsKit
import Testing

@Suite("DriverProtocolConformance")
struct DriverProtocolConformanceTests {

    /// Verifies T42 — every registered driver implements the required protocol
    /// surface. A compile-time-visible assertion: if the driver ever drops
    /// a method, this file stops compiling.
    @Test(
        "every vendor implements SecretRotationDriver rotate + invalidate",
        arguments: ["ovh", "brevo", "github", "woodpecker"]
    )
    func test_driver_protocolConformance_SecretRotationDriver_allVendorsImplementRequiredMethods(
        vendor: String
    ) async {
        let http = RecordingTransport()
        let driver: any SecretRotationDriver = {
            switch vendor {
            case "ovh":        return DriverOVH(mode: .sandbox, transport: http)
            case "brevo":      return DriverBrevo(transport: http)
            case "github":     return DriverGitHub(transport: http)
            case "woodpecker": return DriverWoodpecker(transport: http)
            default:           fatalError("unknown vendor \(vendor)")
            }
        }()
        #expect(driver.vendor == vendor)

        let entry = makeEntry(vendor: vendor)
        _ = await driver.rotate(entry: entry, trigger: .manual(op: "conformance"))
        try? await driver.invalidate(previous: entry)
    }

    @Test("humanFallback slot is nil for all current drivers")
    func test_driver_humanFallbackSlot_definedOnProtocol_evenIfNilForV1Vendors() {
        let http = RecordingTransport()
        let ovh = DriverOVH(mode: .sandbox, transport: http)
        let brevo = DriverBrevo(transport: http)
        let gh = DriverGitHub(transport: http)
        let wp = DriverWoodpecker(transport: http)

        #expect(ovh.humanFallback == nil)
        #expect(brevo.humanFallback == nil)
        #expect(gh.humanFallback == nil)
        #expect(wp.humanFallback == nil)
    }
}
