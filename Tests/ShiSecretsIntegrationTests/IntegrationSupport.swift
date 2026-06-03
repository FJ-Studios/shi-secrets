import Crypto
import Foundation
@testable import ShiSecretsBrokerd
import ShiSecretsKit

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// Shared helpers for the in-process broker integration tests.
//
// W1 update (shi-secrets W1 — 2026-05-21):
//   IntegFakeProcessHandle / IntegFakeProcessLauncher REMOVED — bw CLI gone.
//   IntegStubBootstrap updated to async unseal() returning VaultwardenClient.
//   InMemoryBWClient wired via activate() instead of start(session:).

/// Review finding U13 — in-process integration tests inject a stub
/// BootstrapProvider that always succeeds without touching the Keychain.
struct IntegStubBootstrap: BootstrapProvider {
    func unseal() async throws -> (vaultClient: VaultwardenClient, signingKey: BrokerSigningKey) {
        let creds = VaultwardenCredentials(
            clientID: "user.integ",
            clientSecret: "integ-secret",
            serverURL: URL(string: "https://vw.obyw.one")!
        )
        let client = try VaultwardenClient(credentials: creds, configYmlVaultServer: "https://vw.obyw.one")
        return (client, BrokerSigningKey(privateKey: Curve25519.Signing.PrivateKey()))
    }
}

struct IntegBrokerStack: Sendable {
    let daemon: BrokerDaemon
    let bwClient: InMemoryBWClient
    let socket: UnixSocketServer
    let kernel: ShikkiKernel
    let audit: AuditWriter
    let seams: SeamsWriter
    let registry: TokenRegistry
    let minter: TokenMinter
    let manifestStore: ManifestStore
    let manifestPrivateKey: Curve25519.Signing.PrivateKey
    let manifestVerifier: ManifestVerifier
}

enum IntegSupport {

    static func socketPath() -> String {
        "/tmp/sh-i-\(UUID().uuidString.prefix(8)).s"
    }

    /// Build an in-process broker stack wired for integration tests.
    static func makeStack(
        scopeAllowlist: [String] = ["ovh/OVH_APP_KEY", "brevo/BREVO_API_KEY", "github/GH_PAT"],
        manifest: [ManifestVerifier.ToolEntry] = [],
        sessionValid: Bool = true
    ) async throws -> IntegBrokerStack {
        let kernel = ShikkiKernel()
        let audit = AuditWriter()
        let seams = SeamsWriter()
        let registry = TokenRegistry()
        let drivers = DriverRegistry()
        let engine = RotationEngine(
            drivers: drivers, audit: audit, seams: seams, registry: registry
        )
        let manifestPrivate = Curve25519.Signing.PrivateKey()
        let verifier = ManifestVerifier(pinnedPublicKey: manifestPrivate.publicKey)
        let manifestStore = ManifestStore(verifier: verifier, seams: seams)
        let scopeValidator = try ScopeValidator(allowlist: scopeAllowlist)
        let bridge = MCPBridge(bearerAllowlist: ["bearer-1"])
        let socket = UnixSocketServer(
            config: UnixSocketConfig(
                socketPath: socketPath(),
                expectedMode: 0o600,
                expectedUid: UInt32(geteuid())
            )
        )
        // W1: InMemoryBWClient uses activate() — no subprocess, no BW_SESSION.
        let bwClient = InMemoryBWClient()
        if sessionValid {
            await bwClient.activate()
        }
        let signingKey = Curve25519.Signing.PrivateKey()
        let minter = TokenMinter(
            registry: registry, signingKey: signingKey, toolManifest: manifest
        )
        let daemon = BrokerDaemon(
            kernel: kernel, audit: audit, seams: seams, registry: registry,
            drivers: drivers, engine: engine,
            manifestStore: manifestStore, scopeValidator: scopeValidator,
            bridge: bridge, socket: socket, bwClient: bwClient, minter: minter,
            bootstrap: IntegStubBootstrap()
        )
        return IntegBrokerStack(
            daemon: daemon, bwClient: bwClient, socket: socket, kernel: kernel,
            audit: audit, seams: seams, registry: registry, minter: minter,
            manifestStore: manifestStore,
            manifestPrivateKey: manifestPrivate,
            manifestVerifier: verifier
        )
    }

    static func signedManifest(
        using key: Curve25519.Signing.PrivateKey,
        version: String = "v1.0",
        tools: [ManifestVerifier.ToolEntry] = []
    ) throws -> (bytes: Data, signature: Data) {
        let manifest = ManifestVerifier.Manifest(
            version: version,
            issuedAt: Date(timeIntervalSince1970: 1_777_000_000),
            tools: tools
        )
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let bytes = try encoder.encode(manifest)
        let sig = try key.signature(for: bytes)
        return (bytes, Data(sig))
    }

    static func tearDown(_ stack: IntegBrokerStack) async {
        await stack.socket.shutdown()
    }
}
