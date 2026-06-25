// DoctorCommandTests — W9 spec test IDs.
//
// T-W9-05 → multi-pid detect + fix
// T-W9-06 → adhoc-signed detect + refused fix (surface re-sign cmd)
// T-W9-07 → orphaned socket detect + fix

import Foundation
import Testing
@testable import ShiSecrets

// MARK: - Stub brokerd probe / controller (independent of W8 fakes)

struct ProbeFake: BrokerdProbing {
    var _pids: [Int] = []
    var _socketBound: Bool = true
    func pids() -> [Int] { _pids }
    func socketBound() -> Bool { _socketBound }
    func cacheModifiedAt() -> Date? { nil }
    func cacheTTLMinutes() -> Int? { nil }
    func vaultHost() -> String? { nil }
    func vaultProbe() -> VaultHealth { .unreachable }
    func lastSyncAt() -> Date? { nil }
}

final class RecordingController: BrokerdControlling, @unchecked Sendable {
    var bootoutCalls: [(String, String)] = []
    var bootstrapCalls: [(String, String)] = []
    func bootstrap(plistPath: String, uid: String) throws -> Int32 {
        bootstrapCalls.append((plistPath, uid)); return 0
    }
    func bootout(label: String, uid: String) throws -> Int32 {
        bootoutCalls.append((label, uid)); return 0
    }
    func socketExists(at path: String) -> Bool { false }
}

struct StubCodesignFake: CodesignVerifying {
    let team: String?
    func teamIdentifier(forBinaryAt path: String) -> String? { team }
}

// MARK: - D-05 multi-pid

@Suite("W9 DoctorCheckMultiPid — T-W9-05")
struct DoctorCheckMultiPidTests {

    @Test("detect: 1 PID → clean")
    func singlePid() {
        var probe = ProbeFake(); probe._pids = [1234]
        let check = DoctorCheckMultiPid(probe: probe, controller: RecordingController())
        #expect(check.detect() == .clean)
    }

    @Test("detect: 2 PIDs → issue with detail")
    func multiPid() {
        var probe = ProbeFake(); probe._pids = [1234, 5678]
        let check = DoctorCheckMultiPid(probe: probe, controller: RecordingController())
        if case .issue(let d) = check.detect() {
            #expect(d.contains("2 brokerd PIDs"))
        } else { Issue.record("expected .issue") }
    }

    @Test("fix: dryRun reports planned action without calling launchctl")
    func dryRun() {
        var probe = ProbeFake(); probe._pids = [1234, 5678]
        let controller = RecordingController()
        let check = DoctorCheckMultiPid(probe: probe, controller: controller)
        let result = check.fix(dryRun: true)
        if case .fixed(let action) = result {
            #expect(action.contains("bootout"))
        } else { Issue.record("expected .fixed in dryRun") }
        #expect(controller.bootoutCalls.isEmpty)
        #expect(controller.bootstrapCalls.isEmpty)
    }

    @Test("fix: actual fix boots out all labels + bootstraps canonical")
    func actualFix() {
        var probe = ProbeFake(); probe._pids = [1234, 5678]
        let controller = RecordingController()
        let check = DoctorCheckMultiPid(probe: probe, controller: controller)
        let result = check.fix(dryRun: false)
        if case .fixed = result { /* ok */ } else { Issue.record("expected .fixed") }
        let labels = controller.bootoutCalls.map { $0.0 }
        #expect(labels.contains(PlistPathPolicy.canonicalLabel))
        for legacy in PlistPathPolicy.legacyLabels { #expect(labels.contains(legacy)) }
        #expect(controller.bootstrapCalls.count == 1)
    }
}

// MARK: - D-06 adhoc-signed

@Suite("W9 DoctorCheckAdhocSigned — T-W9-06")
struct DoctorCheckAdhocSignedTests {

    @Test("detect: OBYW.ONE TeamID → clean")
    func okSigned() {
        let cs = StubCodesignFake(team: CodesignAssertion.expectedTeamID)
        let check = DoctorCheckAdhocSigned(binaryPath: "/tmp/x", verifier: cs)
        #expect(check.detect() == .clean)
    }

    @Test("detect: adhoc → issue")
    func adhocDetected() {
        let cs = StubCodesignFake(team: nil)
        let check = DoctorCheckAdhocSigned(binaryPath: "/tmp/x", verifier: cs)
        if case .issue(let d) = check.detect() {
            #expect(d.contains("adhoc"))
        } else { Issue.record("expected .issue") }
    }

    @Test("fix: refuses + surfaces operator-runnable codesign command")
    func refusesFix() {
        let cs = StubCodesignFake(team: nil)
        let check = DoctorCheckAdhocSigned(binaryPath: "/tmp/x", verifier: cs)
        let result = check.fix(dryRun: false)
        if case .refused(let reason) = result {
            #expect(reason.contains("codesign"))
            #expect(reason.contains("SH7MZH647S"))
        } else { Issue.record("expected .refused") }
    }
}

// MARK: - D-07 orphaned socket

@Suite("W9 DoctorCheckOrphanedSocket — T-W9-07")
struct DoctorCheckOrphanedSocketTests {

    @Test("detect: socket absent → clean")
    func absentSocket() {
        let tmpPath = "/tmp/nonexistent-doctor-socket-\(UUID().uuidString)"
        let check = DoctorCheckOrphanedSocket(probe: ProbeFake(), socketPath: tmpPath)
        #expect(check.detect() == .clean)
    }

    @Test("detect: socket exists + no PIDs → orphan")
    func orphanDetected() throws {
        // Create a temp regular file at a unique path; doctor checks file existence,
        // not file type, for this fixture.
        let tmpPath = "/tmp/orphan-socket-\(UUID().uuidString)"
        FileManager.default.createFile(atPath: tmpPath, contents: Data())
        defer { try? FileManager.default.removeItem(atPath: tmpPath) }
        let check = DoctorCheckOrphanedSocket(probe: ProbeFake(), socketPath: tmpPath)
        if case .issue = check.detect() { /* ok */ } else { Issue.record("expected .issue") }
    }

    @Test("fix: removes orphan socket file")
    func removesOrphan() throws {
        let tmpPath = "/tmp/orphan-fix-\(UUID().uuidString)"
        FileManager.default.createFile(atPath: tmpPath, contents: Data())
        let check = DoctorCheckOrphanedSocket(probe: ProbeFake(), socketPath: tmpPath)
        let result = check.fix(dryRun: false)
        if case .fixed = result { /* ok */ } else { Issue.record("expected .fixed, got \(result)") }
        #expect(!FileManager.default.fileExists(atPath: tmpPath))
    }
}

// MARK: - DoctorCommand orchestrator

@Suite("W9 DoctorCommand — orchestrator")
struct DoctorCommandOrchestratorTests {

    @Test("runDetect: each check produces a report")
    func detectsAllChecks() {
        var probe = ProbeFake(); probe._pids = [1234]
        let cs = StubCodesignFake(team: CodesignAssertion.expectedTeamID)
        let checks: [any DoctorCheck] = [
            DoctorCheckMultiPid(probe: probe, controller: RecordingController()),
            DoctorCheckAdhocSigned(binaryPath: "/tmp/x", verifier: cs),
        ]
        let cmd = DoctorCommand(checks: checks)
        let reports = cmd.runDetect()
        #expect(reports.count == 2)
        for r in reports { #expect(r.finding == .clean) }
    }

    @Test("runFix: clean checks emit .noop; issue checks emit fix result")
    func fixesOnlyDirty() {
        var probe = ProbeFake(); probe._pids = [1234, 5678] // dirty for multi-pid
        let cs = StubCodesignFake(team: CodesignAssertion.expectedTeamID) // clean for adhoc
        let checks: [any DoctorCheck] = [
            DoctorCheckMultiPid(probe: probe, controller: RecordingController()),
            DoctorCheckAdhocSigned(binaryPath: "/tmp/x", verifier: cs),
        ]
        let cmd = DoctorCommand(checks: checks)
        let reports = cmd.runFix(dryRun: true)
        let cleanCount = reports.filter { $0.fix == .noop }.count
        let actedCount = reports.filter {
            if case .some(.fixed) = $0.fix { return true } else { return false }
        }.count
        #expect(cleanCount == 1)
        #expect(actedCount == 1)
    }
}
