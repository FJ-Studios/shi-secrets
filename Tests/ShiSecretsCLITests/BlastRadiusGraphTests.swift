import Foundation
@testable import ShiSecretsCLI
import ShiSecretsClient
@testable import ShiSecretsKit
import Testing

@Suite("BlastRadiusGraph")
struct BlastRadiusGraphTests {

    @Test("blast-radius — scope graph snapshot — 3 dependents tree")
    func test_cli_blastRadius_renderScopeGraph_snapshot() {
        let report = BlastRadiusReport(
            rootJti: "01JC0ABC000000000000000K7P",
            sub: "ci@nuc-dev",
            scope: "ovh/dns/*",
            dependents: [
                .init(jti: "01JC0ABC000000000000000K7Q", scope: "ovh/dns/*"),
                .init(jti: "01JC0ABC000000000000000X9M", scope: "ovh/compute/*"),
                .init(jti: "01JC0ABC000000000000000P2F", scope: "ovh/billing/*"),
            ]
        )
        let rendered = BlastRadiusGraph.render(report)
        // Review finding #11 — symmetric 4/4 ellipsis: `01JC…0K7P`.
        let expected = """
        root  jti=01JC…0K7P  sub=ci@nuc-dev  scope=ovh/dns/*
        ├─ 01JC…0K7Q  scope=ovh/dns/*
        ├─ 01JC…0X9M  scope=ovh/compute/*
        └─ 01JC…0P2F  scope=ovh/billing/*
        """
        #expect(rendered == expected)
    }

    @Test("blast-radius — computes read-only report without mutating TokenRegistry")
    func test_blastRadius_rendersScopeGraph_withoutMutation() async throws {
        let registry = TokenRegistry()
        let baseNbf = Date(timeIntervalSince1970: 1_000_000)
        let diesAt = baseNbf.addingTimeInterval(600)
        let row1 = TokenRegistry.Row(
            jti: "01JC0ABC000000000000000K7P",
            sub: "ci@nuc-dev",
            scope: "ovh/dns/*",
            op: .read,
            nbf: baseNbf, diesAt: diesAt,
            llmTouched: false,
            passkeyPath: false
        )
        let row2 = TokenRegistry.Row(
            jti: "01JC0ABC000000000000000K7Q",
            sub: "ci@nuc-dev",
            scope: "ovh/compute/*",
            op: .read,
            nbf: baseNbf, diesAt: diesAt,
            llmTouched: false,
            passkeyPath: false
        )
        let row3 = TokenRegistry.Row(
            jti: "01JC0ABC000000000000000X9M",
            sub: "someone-else@nuc-dev",
            scope: "ovh/billing/*",
            op: .read,
            nbf: baseNbf, diesAt: diesAt,
            llmTouched: false,
            passkeyPath: false
        )
        try await registry.insert(row1)
        try await registry.insert(row2)
        try await registry.insert(row3)

        let rows = await registry.all()
        let report = BlastRadiusGraph.compute(rows: rows, rootJti: row1.jti)
        #expect(report != nil)
        #expect(report?.sub == "ci@nuc-dev")
        #expect(report?.dependents.count == 1)  // row2 shares sub, row3 doesn't
        #expect(report?.dependents.first?.scope == "ovh/compute/*")

        // Confirm registry untouched.
        let after = await registry.all()
        #expect(after.count == 3)
        #expect(await registry.isRevoked(jti: row1.jti) == false)
    }
}
