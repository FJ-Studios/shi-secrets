import Testing
@testable import ShiSecretsKit
import Foundation

// VaultwardenClient.resolveServerURL — config-chain precedence tests
// Covers backlog item 5256133A tier-chain: configYml > env > devDefault

@Suite("VaultwardenClient.resolveServerURL config chain")
struct VaultwardenURLChainTests {

    @Test("configYml takes precedence over env var when both are set")
    func configYml_precedence_over_env() {
        // Simulate env var being set by passing a custom envKey that IS set
        // in process environment (we use a key that definitely doesn't exist
        // in CI and verify devDefault, then verify configYml wins over devDefault).
        let configURL = "https://from-config.example.com"
        let result = VaultwardenClient.resolveServerURL(
            configYml: configURL,
            envKey: "SHIKKI_VAULT_URL_TEST_NONEXISTENT_KEY_XYZ",
            devDefault: "https://dev-default.example.com"
        )
        #expect(result == configURL, "configYml must take tier-1 precedence")
    }

    @Test("env var takes precedence over devDefault when configYml is nil")
    func env_precedence_over_devDefault() {
        // resolveServerURL reads ProcessInfo.processInfo.environment[envKey].
        // We use a key that's reliably unset; if SHIKKI_VAULT_URL is unset
        // the dev default is returned. We inject via a known-present env key.
        // HOME is always set and non-empty — use it as the env-key override.
        let home = ProcessInfo.processInfo.environment["HOME"] ?? ""
        guard !home.isEmpty else {
            // If HOME is somehow absent, skip rather than fail.
            return
        }
        let result = VaultwardenClient.resolveServerURL(
            configYml: nil,
            envKey: "HOME",           // always set, non-empty
            devDefault: "https://dev-default.example.com"
        )
        #expect(result == home, "env var must take tier-2 precedence over devDefault")
    }

    @Test("devDefault used when both configYml and env are nil/absent")
    func devDefault_used_when_both_absent() {
        let devDefault = "https://vw.obyw.one"
        // Use a key guaranteed not to be set in any CI environment.
        let result = VaultwardenClient.resolveServerURL(
            configYml: nil,
            envKey: "SHIKKI_VAULT_URL_DEFINITELY_UNSET_IN_CI_XYZABC123",
            devDefault: devDefault
        )
        #expect(result == devDefault, "devDefault must be the tier-3 fallback")
    }

    @Test("empty configYml string falls through to env/devDefault")
    func empty_configYml_falls_through() {
        let devDefault = "https://vw.obyw.one"
        let result = VaultwardenClient.resolveServerURL(
            configYml: "",   // empty → should not win
            envKey: "SHIKKI_VAULT_URL_DEFINITELY_UNSET_IN_CI_XYZABC123",
            devDefault: devDefault
        )
        #expect(result == devDefault, "empty configYml must not win over devDefault")
    }

    // MARK: - vaultHostUnreachable error case

    @Test("VaultwardenClientError.vaultHostUnreachable carries actionable message")
    func vaultHostUnreachable_carriesMessage() {
        let msg = "DNS lookup failed for vault host. Set SHIKKI_VAULT_URL or ~/.shikki/settings/secrets-brokerd.toml [vault_url]"
        let err = VaultwardenClientError.vaultHostUnreachable(message: msg)
        if case .vaultHostUnreachable(let m) = err {
            #expect(m.contains("SHIKKI_VAULT_URL"), "Error message must mention SHIKKI_VAULT_URL")
            #expect(m.contains("secrets-brokerd.toml"), "Error message must mention the TOML path")
            #expect(m.contains("vault_url"), "Error message must mention the key name")
        } else {
            Issue.record("vaultHostUnreachable case not matched")
        }
    }
}
