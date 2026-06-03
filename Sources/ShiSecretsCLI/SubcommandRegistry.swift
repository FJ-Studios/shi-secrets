import Foundation

// SubcommandRegistry — top-level `shi` CLI registration surface (T64).
//
// The spec locates this file at `apps/shi/Sources/shi/SubcommandRegistry.swift`.
// That app target does not exist in this worktree; the CLI-layer exposes
// the three subcommand groups here, and when the top-level `apps/shi/`
// binary lands (separate epic) it imports `ShiSecretsCLI` and
// registers them via `ShiSecretsSubcommandGroups.allGroups`.
//
// Three groups:
//   secret   → `shi secret get/list/set/rotate/revoke`
//   token    → `shi token revoke [--all-bots [--force]]`
//   audit    → `shi audit secrets [--tui|seams]`

public struct SubcommandGroup: Sendable, Equatable {
    public let name: String
    public let subcommands: [String]
    public init(name: String, subcommands: [String]) {
        self.name = name
        self.subcommands = subcommands
    }
}

public enum ShiSecretsSubcommandGroups {

    public static let secretGroup = SubcommandGroup(
        name: "secret",
        subcommands: SecretCommandRegistry.subcommandNames
    )

    public static let tokenGroup = SubcommandGroup(
        name: "token",
        subcommands: TokenCommandRegistry.subcommandNames
    )

    public static let auditSecretsGroup = SubcommandGroup(
        name: "audit-secrets",
        subcommands: AuditSecretsCommandRegistry.subcommandNames
    )

    public static var allGroups: [SubcommandGroup] {
        [secretGroup, tokenGroup, auditSecretsGroup]
    }
}
