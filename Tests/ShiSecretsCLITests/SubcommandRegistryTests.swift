import Foundation
@testable import ShiSecretsCLI
import Testing

@Suite("SubcommandRegistry")
struct SubcommandRegistryTests {

    @Test("shi registers secret group")
    func test_shi_registersSecretGroup() {
        let g = ShiSecretsSubcommandGroups.secretGroup
        #expect(g.name == "secret")
        #expect(g.subcommands == ["fetch", "get", "list", "revoke", "rotate", "set"])
    }

    @Test("shi registers token group")
    func test_shi_registersTokenGroup() {
        let g = ShiSecretsSubcommandGroups.tokenGroup
        #expect(g.name == "token")
        #expect(g.subcommands == ["revoke"])
    }

    @Test("shi registers audit secrets group")
    func test_shi_registersAuditSecretsGroup() {
        let g = ShiSecretsSubcommandGroups.auditSecretsGroup
        #expect(g.name == "audit-secrets")
        #expect(g.subcommands == ["seams", "tui"])
    }

    @Test("allGroups — 3 top-level groups")
    func test_shi_allGroups_hasThree() {
        #expect(ShiSecretsSubcommandGroups.allGroups.count == 3)
    }
}
