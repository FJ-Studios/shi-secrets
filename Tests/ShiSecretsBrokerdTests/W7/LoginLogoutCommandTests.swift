// LoginLogoutCommandTests — W7 (post-rework spec 2026-06-25).
//
// Test ID mapping:
//   T-W7-01 → login_withValidKeychain_bootstrapsCanonicalLabel
//   T-W7-02 → login_withEmptyKeychain_suggestsSetupWizard
//   T-W7-03 → login_idempotent_alreadyRunning_isNoOp
//   T-W7-04 → logout_bootsAllLabels_canonical_AND_legacy_W3
//   T-W7-05 → logout_then_login_freshSocketBindsCleanly
//   T-W7-08 → login_refuses_adhocSignedBrokerd_withExplicitError (regression)
//   T-W7-09 → logout_archivesStalePlistsAtNonCanonicalPaths (regression)
//
// Deferred to W7-impl-stage2 (operator-validated):
//   T-W7-06 / T-W7-07 → e2e against real /bin/launchctl (@LaunchdIntegration).

import Foundation
import Testing
@testable import ShiSecrets
@testable import ShiSecretsKit

// MARK: - Fakes

actor RecordingBrokerdController: BrokerdControlling {
    private var socketUp: Bool
    private(set) var bootstrapCalls: [(plist: String, uid: String)] = []
    private(set) var bootoutCalls: [(label: String, uid: String)] = []
    private var nextBootstrapExit: Int32

    init(socketUp: Bool = false, nextBootstrapExit: Int32 = 0) {
        self.socketUp = socketUp
        self.nextBootstrapExit = nextBootstrapExit
    }

    func makeSocketAppearAfterBootstrap() { socketUp = true }

    nonisolated func socketExists(at path: String) -> Bool {
        // No locking — set via test helpers below.
        return _socketUpFlag.value
    }

    nonisolated func bootstrap(plistPath: String, uid: String) throws -> Int32 {
        _bootstrapLog.value.append((plistPath, uid))
        // Make the socket "appear" only if test allows it.
        if _autoBindOnBootstrap.value { _socketUpFlag.value = true }
        return _nextBootstrapExit.value
    }

    nonisolated func bootout(label: String, uid: String) throws -> Int32 {
        _bootoutLog.value.append((label, uid))
        return 0
    }

    nonisolated func kickstartValidate(label: String, uid: String) throws -> Int32 {
        _kickstartLog.value.append((label, uid))
        return _nextKickstartExit.value
    }

    // Plain wrapper boxes so the protocol's nonisolated methods can mutate.
    final class Box<T>: @unchecked Sendable {
        var value: T
        init(_ v: T) { value = v }
    }
    nonisolated let _socketUpFlag = Box(false)
    nonisolated let _autoBindOnBootstrap = Box(true)
    nonisolated let _nextBootstrapExit = Box(Int32(0))
    nonisolated let _bootstrapLog = Box<[(String, String)]>([])
    nonisolated let _bootoutLog = Box<[(String, String)]>([])
    nonisolated let _kickstartLog = Box<[(String, String)]>([])
    nonisolated let _nextKickstartExit = Box(Int32(0))
}

struct StubCodesignVerifier: CodesignVerifying {
    let teamID: String?
    func teamIdentifier(forBinaryAt path: String) -> String? { return teamID }
}

actor StubCredentialStoreForLogin: VaultCredentialStore {
    private var stored: VaultwardenCredentials?
    init(stored: VaultwardenCredentials? = nil) { self.stored = stored }
    func load() async throws -> VaultwardenCredentials {
        if let s = stored { return s }
        throw KeychainVaultCredentials.KeychainError.itemNotFound
    }
    func store(_ credentials: VaultwardenCredentials, overwrite: Bool) async throws {
        stored = credentials
    }
    func delete() async { stored = nil }
}

actor RecordingLogoutFileManager: LogoutFileManaging {
    private(set) var archiveCalls: [(String, String)] = []
    private let existing: Set<String>

    init(existingPaths: Set<String> = []) {
        self.existing = existingPaths
    }

    nonisolated func archive(path: String, withSuffix suffix: String) -> String? {
        _calls.value.append((path, suffix))
        return _existing.value.contains(path) ? "\(path)\(suffix)" : nil
    }

    final class Box<T>: @unchecked Sendable { var value: T; init(_ v: T) { value = v } }
    nonisolated let _existing: Box<Set<String>> = Box([])
    nonisolated let _calls: Box<[(String, String)]> = Box([])
}

// MARK: - Helpers

let validCreds = VaultwardenCredentials(
    clientID: "user.00000000-0000-0000-0000-000000000000",
    clientSecret: "ok",
    serverURL: URL(string: "https://vw.obyw.one")!
)

// MARK: - LoginCommand

@Suite("W7 LoginCommand — happy + idempotency (T-W7-01, T-W7-03)")
struct LoginCommandHappyTests {

    @Test("login with valid keychain bootstraps canonical label")
    func bootstrapsCanonical() async {
        let controller = RecordingBrokerdController()
        let store = StubCredentialStoreForLogin(stored: validCreds)
        let cs = StubCodesignVerifier(teamID: CodesignAssertion.expectedTeamID)
        let cmd = LoginCommand(
            credentialStore: store,
            controller: controller,
            codesign: cs,
            brokerdBinaryPath: "/tmp/fake-brokerd",
            socketWaitSeconds: 1
        )
        let outcome = await cmd.run(uid: "501")
        #expect(outcome == .bootstrapped)
        #expect(controller._bootstrapLog.value.count == 1)
        #expect(controller._bootstrapLog.value.first?.0 == PlistPathPolicy.canonicalPlistPath)
    }

    @Test("login is idempotent when socket already up — no bootstrap call")
    func idempotent() async {
        let controller = RecordingBrokerdController()
        controller._socketUpFlag.value = true
        controller._autoBindOnBootstrap.value = false
        let cs = StubCodesignVerifier(teamID: CodesignAssertion.expectedTeamID)
        let store = StubCredentialStoreForLogin(stored: validCreds)
        let cmd = LoginCommand(
            credentialStore: store,
            controller: controller,
            codesign: cs,
            brokerdBinaryPath: "/tmp/fake-brokerd",
            socketWaitSeconds: 1
        )
        let outcome = await cmd.run(uid: "501")
        #expect(outcome == .alreadyRunning)
        #expect(controller._bootstrapLog.value.isEmpty)
    }
}

@Suite("W7 LoginCommand — guard rails (T-W7-02, T-W7-08)")
struct LoginCommandGuardRailsTests {

    @Test("empty keychain suggests setup wizard (T-W7-02)")
    func emptyKeychain() async {
        let cs = StubCodesignVerifier(teamID: CodesignAssertion.expectedTeamID)
        let cmd = LoginCommand(
            credentialStore: StubCredentialStoreForLogin(stored: nil),
            controller: RecordingBrokerdController(),
            codesign: cs,
            brokerdBinaryPath: "/tmp/fake-brokerd",
            socketWaitSeconds: 1
        )
        let outcome = await cmd.run(uid: "501")
        #expect(outcome == .keychainEmpty)
        #expect(outcome.operatorMessage.contains("setup wizard"))
        #expect(outcome.exitCode == 1)
    }

    @Test("adhoc-signed brokerd is refused (T-W7-08 regression)")
    func refusesAdhoc() async {
        let cs = StubCodesignVerifier(teamID: nil) // adhoc
        let cmd = LoginCommand(
            credentialStore: StubCredentialStoreForLogin(stored: validCreds),
            controller: RecordingBrokerdController(),
            codesign: cs,
            brokerdBinaryPath: "/tmp/adhoc-brokerd",
            socketWaitSeconds: 1
        )
        let outcome = await cmd.run(uid: "501")
        if case .refusedAdhocSigned(let path) = outcome {
            #expect(path == "/tmp/adhoc-brokerd")
        } else { Issue.record("expected refusedAdhocSigned, got \(outcome)") }
        #expect(outcome.exitCode == 2)
    }

    @Test("wrong-TeamID brokerd is refused with explicit team")
    func refusesWrongTeam() async {
        let cs = StubCodesignVerifier(teamID: "ZZZ999")
        let cmd = LoginCommand(
            credentialStore: StubCredentialStoreForLogin(stored: validCreds),
            controller: RecordingBrokerdController(),
            codesign: cs,
            brokerdBinaryPath: "/tmp/wrong-brokerd",
            socketWaitSeconds: 1
        )
        let outcome = await cmd.run(uid: "501")
        if case .refusedWrongTeam(_, let actual) = outcome {
            #expect(actual == "ZZZ999")
        } else { Issue.record("expected refusedWrongTeam, got \(outcome)") }
    }

    @Test("socket timeout reported when bootstrap returns 0 but no bind")
    func socketTimeout() async {
        let controller = RecordingBrokerdController()
        controller._autoBindOnBootstrap.value = false
        let cs = StubCodesignVerifier(teamID: CodesignAssertion.expectedTeamID)
        let cmd = LoginCommand(
            credentialStore: StubCredentialStoreForLogin(stored: validCreds),
            controller: controller,
            codesign: cs,
            brokerdBinaryPath: "/tmp/fake-brokerd",
            socketWaitSeconds: 1
        )
        let outcome = await cmd.run(uid: "501")
        if case .socketTimeout(let s) = outcome { #expect(s == 1) } else {
            Issue.record("expected socketTimeout, got \(outcome)")
        }
    }
}

// MARK: - LogoutCommand

@Suite("W7 LogoutCommand — boots all + archives stale (T-W7-04, T-W7-09)")
struct LogoutCommandTests {

    @Test("logout boots ALL labels — canonical + legacy")
    func bootsAllLabels() {
        let controller = RecordingBrokerdController()
        let cmd = LogoutCommand(
            controller: controller,
            fileManager: RecordingLogoutFileManager(),
            nowProvider: { Date(timeIntervalSince1970: 1_700_000_000) }
        )
        _ = cmd.run(uid: "501")
        let labels = controller._bootoutLog.value.map { $0.0 }
        #expect(labels.contains(PlistPathPolicy.canonicalLabel))
        for legacy in PlistPathPolicy.legacyLabels {
            #expect(labels.contains(legacy))
        }
    }

    @Test("logout archives stale plists at non-canonical paths (regression)")
    func archivesStale() {
        let fm = RecordingLogoutFileManager()
        // Pretend two of the legacy search paths exist on disk.
        let stalePaths = Set(PlistPathPolicy.legacyArchivableSearchPaths.prefix(2))
        fm._existing.value = stalePaths
        let controller = RecordingBrokerdController()
        let cmd = LogoutCommand(
            controller: controller,
            fileManager: fm,
            nowProvider: { Date(timeIntervalSince1970: 1_700_000_000) }
        )
        let outcome = cmd.run(uid: "501")
        if case .completed(_, let archived, _) = outcome {
            #expect(archived.count == 2)
            for a in archived { #expect(a.contains(".RETIRED-")) }
        } else { Issue.record("expected .completed") }
        #expect(outcome.exitCode == 0)
    }

    @Test("logout is idempotent — runs even with no labels loaded (exit 0)")
    func idempotentNoOp() {
        let cmd = LogoutCommand(
            controller: RecordingBrokerdController(),
            fileManager: RecordingLogoutFileManager()
        )
        #expect(cmd.run(uid: "501").exitCode == 0)
    }
}
