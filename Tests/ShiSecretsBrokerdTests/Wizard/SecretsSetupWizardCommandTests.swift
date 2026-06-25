// SecretsSetupWizardCommandTests — W6 one-click bootstrap wizard.
//
// Unit-tests are scoped to the pieces we can hermetically exercise:
//   - WizardError.exitCode / .message / .hint contracts
//   - WizardInputs equality / Sendable
//   - collectInputs() flow — valid, invalid client_id, invalid URL
// The launchctl-bootstrap path, socket-wait, and live smoke are covered
// by ShiSecretsE2ETests; here we keep the unit envelope tight.
//
// W6 — spec e8c4a921-7d3b-4f5e-9a2c-1d6b8f4e3a91

import Foundation
import Testing
@testable import ShiSecrets

@Suite("W6 setup wizard — typed-error contract")
struct WizardErrorContractTests {

    @Test("exitCode matches typed-failure family")
    func exitCodeFamilies() {
        #expect(WizardError.missingInput(field: "x").exitCode == 1)
        #expect(WizardError.invalidClientID("nope").exitCode == 1)
        #expect(WizardError.invalidServerURL("nope").exitCode == 1)
        #expect(WizardError.keychainOSError(status: -25300).exitCode == 2)
        #expect(WizardError.seederFailed(message: "x").exitCode == 2)
        #expect(WizardError.launchctlBootstrap(exitCode: 1, stderr: "x").exitCode == 3)
        #expect(WizardError.processSpawnFailed(executable: "/x", reason: "y").exitCode == 3)
        #expect(WizardError.socketNeverAppeared(timeoutSeconds: 5, path: "/tmp/x").exitCode == 4)
        #expect(WizardError.smokeMismatch(expected: "a", got: "b").exitCode == 5)
    }

    @Test("invalid client_id message hints the user.* prefix")
    func invalidClientIDHint() {
        let e = WizardError.invalidClientID("bogus")
        #expect(e.message.contains("invalid client_id"))
        let hint = e.hint ?? ""
        #expect(hint.contains("user."))
    }

    @Test("errSecItemNotFound has a tailored hint")
    func errSecItemNotFoundHint() {
        let e = WizardError.keychainOSError(status: -25300)
        #expect(e.hint?.contains("errSecItemNotFound") == true)
    }

    @Test("socketNeverAppeared message includes timeout + path")
    func socketTimeoutMessage() {
        let e = WizardError.socketNeverAppeared(timeoutSeconds: 30, path: "/tmp/sock")
        #expect(e.message.contains("30"))
        #expect(e.message.contains("/tmp/sock"))
    }
}

@Suite("W6 setup wizard — input collection")
struct WizardInputCollectionTests {

    @Test("collectInputs accepts user.<UUID> client_id + https URL")
    func happyPath() {
        let cmd = SecretsSetupWizardCommand(
            clientID: "user.00000000-0000-0000-0000-000000000000",
            serverURL: "https://vw.obyw.one",
            clientSecretArg: "deadbeef-secret",
            skipSmoke: true
        )
        switch cmd.collectInputs() {
        case .success(let inputs):
            #expect(inputs.clientID.hasPrefix("user."))
            #expect(inputs.serverURL.scheme == "https")
            #expect(inputs.clientSecret == "deadbeef-secret")
        case .failure(let e):
            Issue.record("Expected success, got \(e.message)")
        }
    }

    @Test("collectInputs rejects client_id without user. prefix")
    func rejectsBadClientID() {
        let cmd = SecretsSetupWizardCommand(
            clientID: "no-prefix-uuid",
            serverURL: "https://vw.obyw.one",
            clientSecretArg: "x",
            skipSmoke: true
        )
        switch cmd.collectInputs() {
        case .success:
            Issue.record("Should have failed")
        case .failure(let e):
            #expect(e == .invalidClientID("no-prefix-uuid"))
        }
    }

    @Test("collectInputs rejects non-http(s) server URL")
    func rejectsBadServerURL() {
        let cmd = SecretsSetupWizardCommand(
            clientID: "user.00000000-0000-0000-0000-000000000000",
            serverURL: "ftp://vw.obyw.one",
            clientSecretArg: "x",
            skipSmoke: true
        )
        switch cmd.collectInputs() {
        case .success:
            Issue.record("Should have failed on ftp:// URL")
        case .failure(let e):
            #expect(e == .invalidServerURL("ftp://vw.obyw.one"))
        }
    }
}

@Suite("W6 setup wizard — WizardInputs value semantics")
struct WizardInputsTests {

    @Test("WizardInputs is Equatable and Sendable")
    func equatableSendable() {
        let a = WizardInputs(
            clientID: "user.abc",
            clientSecret: "s1",
            serverURL: URL(string: "https://x")!
        )
        let b = WizardInputs(
            clientID: "user.abc",
            clientSecret: "s1",
            serverURL: URL(string: "https://x")!
        )
        let c = WizardInputs(
            clientID: "user.xyz",
            clientSecret: "s1",
            serverURL: URL(string: "https://x")!
        )
        #expect(a == b)
        #expect(a != c)
    }
}
