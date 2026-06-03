import Foundation
import ShiSecretsKit
import ShiSecretsClient

// AuditSecretsCommand — `shi audit secrets …` subcommand surface (T62, T63).
//
// Subcommands:
//   (default)   --tui    Katagami-free 3-state dashboard
//   seams               Golden Seam Ledger view
//
// Keeps the CLI composition at the command seam: the BrokerClient
// supplies the raw rows, this command composes them into a render.

public enum AuditSecretsSubcommand: String, Sendable, Equatable, CaseIterable {
    case tui        // default `shi audit secrets --tui`
    case seams
}

public struct AuditSecretsCommand: Sendable {
    public let client: any BrokerClient
    /// Injected dashboard-context provider (tests pin the context;
    /// production derives it from broker telemetry).
    public let dashboardProvider: @Sendable () async -> AuditDashboardContext

    public init(
        client: any BrokerClient,
        dashboardProvider: @escaping @Sendable () async -> AuditDashboardContext
    ) {
        self.client = client
        self.dashboardProvider = dashboardProvider
    }

    public func run(subcommand: AuditSecretsSubcommand) async throws -> CLIOutput {
        var out = CLIOutput()
        switch subcommand {
        case .tui:
            let ctx = await dashboardProvider()
            out.outln(AuditDashboard.render(ctx))
        case .seams:
            let rows = try await client.seamsRows()
            out.outln(SeamsLedgerView.render(rows))
        }
        return out
    }
}

public enum AuditSecretsCommandRegistry {
    public static var subcommandNames: [String] {
        AuditSecretsSubcommand.allCases.map(\.rawValue).sorted()
    }
}
