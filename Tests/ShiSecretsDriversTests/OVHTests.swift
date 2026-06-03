import Foundation
@testable import ShiSecretsDrivers
import ShiSecretsKit
import Testing

@Suite("DriverOVH")
struct DriverOVHTests {

    @Test("rotateAppKey calls the OVH /me/api/credential endpoint in sandbox mode")
    func test_driver_ovh_rotateAppKey_callsRealOvhApi_sandboxMode() async {
        let http = RecordingTransport()
        let bw = RecordingBWClient()
        let driver = DriverOVH(mode: .sandbox, transport: http, bwClient: bw)
        let entry = makeEntry(vendor: "ovh", name: "OVH_APP_KEY")

        let outcome = await driver.rotate(entry: entry, trigger: .manual(op: "rotate"))

        #expect(outcome == .rotated)
        let requests = await http.requests()
        // Sandbox mode must hit the eu.api.ovh.com sandbox host, never prod.
        #expect(requests.contains(where: { $0.url.contains("sandbox") }))
        #expect(requests.contains(where: { $0.url.contains("/me/api/credential") }))
    }

    @Test("rotateAppKey writes the new credential back to the vault entry on success")
    func test_driver_ovh_rotateAppKey_updatesVaultEntry_onSuccess() async {
        let http = RecordingTransport()
        let newKey = "new-ovh-app-key-42"
        let payload = try! JSONSerialization.data(withJSONObject: ["applicationKey": newKey])
        await http.queue(
            match: .init(method: "POST", urlContains: "/me/api/credential"),
            response: DriverHTTPResponse(status: 200, body: payload)
        )
        let bw = RecordingBWClient()
        let driver = DriverOVH(mode: .sandbox, transport: http, bwClient: bw)
        let entry = makeEntry(vendor: "ovh", name: "OVH_APP_KEY")

        let outcome = await driver.rotate(entry: entry, trigger: .scheduled(.warm))

        #expect(outcome == .rotated)
        let writes = await bw.writes()
        #expect(writes.count == 1)
        #expect(writes.first?.name == "OVH_APP_KEY")
        #expect(writes.first?.fields["applicationKey"] == newKey)
    }

    @Test("vendor 500 surfaces .failure and never mutates the vault entry")
    func test_driver_ovh_rotate_vendor500_returnsFailure_noMutation() async {
        let http = RecordingTransport()
        await http.queue(
            match: .init(method: "POST", urlContains: "/me/api/credential"),
            response: DriverHTTPResponse(status: 500)
        )
        let bw = RecordingBWClient()
        let driver = DriverOVH(mode: .sandbox, transport: http, bwClient: bw)
        let entry = makeEntry(vendor: "ovh", name: "OVH_APP_KEY")

        let outcome = await driver.rotate(entry: entry, trigger: .scheduled(.warm))

        guard case .failed = outcome else {
            Issue.record("expected .failed, got \(outcome)")
            return
        }
        let writes = await bw.writes()
        #expect(writes.isEmpty)  // BR-B-04: failure path leaves vault intact
    }
}
