// StatusCommandTests — W8 spec test IDs.
//
// T-W8-01 → green format
// T-W8-02 → cache expired → yellow
// T-W8-03 → brokerd down → red with `shi secrets login` hint
// T-W8-04 → vault 429 cooldown → yellow
// T-W8-05 → --json machine-readable shape
// T-W8-06 → REGRESSION: pid running but socket unbound → red
// T-W8-07 → REGRESSION: two brokerd pids → red + doctor --fix hint

import Foundation
import Testing
@testable import ShiSecrets

struct StubBrokerdProbe: BrokerdProbing {
    var _pids: [Int] = [12345]
    var _socketBound: Bool = true
    var _cacheModifiedAt: Date? = Date(timeIntervalSince1970: 1_700_000_000)
    var _cacheTTLMinutes: Int? = 60
    var _vaultHost: String? = "vw.obyw.one"
    var _vaultProbeResult: VaultHealth = .reachable(host: "vw.obyw.one")
    var _lastSyncAt: Date? = Date(timeIntervalSince1970: 1_700_000_000 - 12)

    func pids() -> [Int] { _pids }
    func socketBound() -> Bool { _socketBound }
    func cacheModifiedAt() -> Date? { _cacheModifiedAt }
    func cacheTTLMinutes() -> Int? { _cacheTTLMinutes }
    func vaultHost() -> String? { _vaultHost }
    func vaultProbe() -> VaultHealth { _vaultProbeResult }
    func lastSyncAt() -> Date? { _lastSyncAt }
}

@Suite("W8 StatusCommand — green path (T-W8-01)")
struct StatusCommandGreenTests {

    @Test("green: brokerd up + cache valid + sync recent → exit 0 + ✓ format")
    func greenPath() {
        let now = Date(timeIntervalSince1970: 1_700_000_000 + 60 * 47)  // 47 minutes after cache
        var probe = StubBrokerdProbe()
        probe._lastSyncAt = Date(timeIntervalSince1970: 1_700_000_000 + 60 * 47 - 12)
        let cmd = StatusCommand(probe: probe, nowProvider: { now })
        let s = cmd.snapshot()
        #expect(s.overall == .green)
        #expect(s.overall.exitCode == 0)
        let line = StatusCommand.render(s)
        #expect(line.hasPrefix("✓"))
        #expect(line.contains("brokerd:up(pid12345)"))
        #expect(line.contains("cache:valid(47m)"))
        #expect(line.contains("vault:vw.obyw.one"))
        #expect(line.contains("sync:"))
    }
}

@Suite("W8 StatusCommand — yellow paths (T-W8-02, T-W8-04)")
struct StatusCommandYellowTests {

    @Test("cache expired → yellow + exit 1")
    func cacheExpired() {
        var probe = StubBrokerdProbe()
        probe._cacheModifiedAt = Date(timeIntervalSince1970: 1_700_000_000)
        probe._cacheTTLMinutes = 10
        let now = Date(timeIntervalSince1970: 1_700_000_000 + 60 * 30) // 30 min later, TTL=10
        let s = StatusCommand(probe: probe, nowProvider: { now }).snapshot()
        if case .expired = s.cache { /* ok */ } else { Issue.record("expected expired") }
        #expect(s.overall == .yellow)
        #expect(s.overall.exitCode == 1)
        #expect(StatusCommand.render(s).contains("cache:EXPIRED"))
    }

    @Test("vault 429 cooldown → yellow")
    func vault429() {
        var probe = StubBrokerdProbe()
        probe._vaultProbeResult = .cooldown429(nextMinutes: 8)
        let s = StatusCommand(probe: probe, nowProvider: { Date(timeIntervalSince1970: 1_700_000_000 + 60 * 5) }).snapshot()
        #expect(s.overall == .yellow)
        #expect(StatusCommand.render(s).contains("429-cooldown(next:8min)"))
    }
}

@Suite("W8 StatusCommand — red paths (T-W8-03, T-W8-06, T-W8-07)")
struct StatusCommandRedTests {

    @Test("brokerd down → red + 'run shi secrets login' hint (T-W8-03)")
    func brokerdDown() {
        var probe = StubBrokerdProbe()
        probe._pids = []
        probe._socketBound = false
        let s = StatusCommand(probe: probe).snapshot()
        if case .downNotLoaded = s.brokerd { /* ok */ } else { Issue.record("expected downNotLoaded") }
        #expect(s.overall == .red)
        #expect(s.overall.exitCode == 2)
        let line = StatusCommand.render(s)
        #expect(line.contains("brokerd:DOWN"))
        #expect(line.contains("shi secrets login"))
    }

    @Test("pid running but socket unbound → red + doctor --fix hint (T-W8-06 regression)")
    func pidNoSocket() {
        var probe = StubBrokerdProbe()
        probe._pids = [12345]
        probe._socketBound = false
        let s = StatusCommand(probe: probe).snapshot()
        if case .pidRunningButSocketUnbound = s.brokerd { /* ok */ } else { Issue.record("expected pidRunningButSocketUnbound") }
        #expect(s.overall == .red)
        #expect(StatusCommand.render(s).contains("doctor --fix"))
    }

    @Test("two brokerd pids → red + doctor --fix hint (T-W8-07 regression)")
    func dualPids() {
        var probe = StubBrokerdProbe()
        probe._pids = [12345, 12346]
        let s = StatusCommand(probe: probe).snapshot()
        if case .multiplePidsRunning(let pids) = s.brokerd {
            #expect(pids.count == 2)
        } else { Issue.record("expected multiplePidsRunning") }
        #expect(s.overall == .red)
        #expect(StatusCommand.render(s).contains("doctor --fix"))
    }
}

@Suite("W8 StatusCommand — --json shape (T-W8-05)")
struct StatusCommandJSONTests {

    @Test("renderJSON has stable keys: brokerd/cache/sync/vault/overall")
    func jsonShape() {
        let s = StatusCommand(probe: StubBrokerdProbe()).snapshot()
        let json = StatusCommand.renderJSON(s)
        #expect(json.contains("\"brokerd\""))
        #expect(json.contains("\"cache\""))
        #expect(json.contains("\"vault\""))
        #expect(json.contains("\"sync\""))
        #expect(json.contains("\"overall\""))
    }
}
