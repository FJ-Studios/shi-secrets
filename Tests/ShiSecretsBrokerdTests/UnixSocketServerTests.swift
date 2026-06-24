import Foundation
@testable import ShiSecretsBrokerd
import Testing

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

@Suite("UnixSocketServer")
struct UnixSocketServerTests {

    private func tempSocketPath() -> String {
        "/tmp/sh-s-\(UUID().uuidString.prefix(8)).s"
    }

    @Test("socket mode 0600 owned by current uid on startup")
    func test_socket_mode0600_ownedByShikkiBroker_onStartup() async throws {
        let path = tempSocketPath()
        let config = UnixSocketConfig(socketPath: path, expectedMode: 0o600, expectedUid: UInt32(geteuid()))
        let server = UnixSocketServer(config: config)
        try await server.start()
        try await server.verifyOnDiskInvariant()

        var st = stat()
        #expect(stat(path, &st) == 0)
        #expect(UInt16(st.st_mode) & 0o777 == 0o600)

        await server.shutdown()
    }

    @Test(
        "mode deviation aborts broker start (not 0600 → error)",
        arguments: [UInt16(0o644), UInt16(0o666), UInt16(0o755)]
    )
    func test_socket_modeDeviation_abortsBrokerStart(mode: UInt16) async throws {
        let path = tempSocketPath()
        let config = UnixSocketConfig(socketPath: path, expectedMode: 0o600, expectedUid: UInt32(geteuid()))
        let server = UnixSocketServer(config: config)
        try await server.start()

        // Manually widen the on-disk mode, then re-verify.
        _ = chmod(path, mode_t(mode))
        do {
            try await server.verifyOnDiskInvariant()
            Issue.record("expected modeMismatch")
        } catch let error as UnixSocketError {
            if case .modeMismatch(let expected, _) = error {
                #expect(expected == 0o600)
            } else {
                Issue.record("expected modeMismatch, got \(error)")
            }
        }
        await server.shutdown()
    }

    @Test("owner deviation aborts broker start")
    func test_socket_ownerDeviation_abortsBrokerStart() async throws {
        let path = tempSocketPath()
        // Configure the server with a bogus expected uid — verifyOnDiskInvariant
        // must trip on the mismatch.
        let wrongUid: UInt32 = UInt32(geteuid()) &+ 99_991
        let config = UnixSocketConfig(socketPath: path, expectedMode: 0o600, expectedUid: wrongUid)
        let server = UnixSocketServer(config: config)

        do {
            try await server.start()
            Issue.record("expected ownerMismatch")
        } catch let error as UnixSocketError {
            if case .ownerMismatch = error {
                // ok
            } else {
                Issue.record("expected ownerMismatch, got \(error)")
            }
        }
        await server.shutdown()
    }

    // MARK: - Orphan socket cleanup (TCP-OSC)

    @Test("TCP-OSC-01: stale socket file present before start — bind succeeds (unlink on startup)")
    func test_socket_staleSocketPresent_startSucceeds() async throws {
        let path = tempSocketPath()
        // Pre-create a stale socket file (simulates a previous crash leaving the socket behind)
        let staleCreated = Foundation.FileManager.default.createFile(atPath: path, contents: nil)
        #expect(staleCreated, "precondition: stale socket file creation should succeed")
        #expect(Foundation.FileManager.default.fileExists(atPath: path), "stale socket must exist before start")

        let config = UnixSocketConfig(socketPath: path, expectedMode: 0o600, expectedUid: UInt32(geteuid()))
        let server = UnixSocketServer(config: config)

        // start() must succeed despite the pre-existing file (it calls unlink first)
        do {
            try await server.start()
        } catch {
            Issue.record("start() must not throw when a stale socket exists; got \(error)")
            return
        }

        // Socket must now exist as a real socket (not the placeholder file)
        var st = stat()
        #expect(stat(path, &st) == 0, "socket file must exist after start")
        #expect(UInt16(st.st_mode) & 0o777 == 0o600, "mode must be 0600")

        await server.shutdown()

        // After shutdown the socket file must be removed
        #expect(!Foundation.FileManager.default.fileExists(atPath: path), "socket file must be removed after shutdown")
    }

    @Test("TCP-OSC-02: shutdown removes socket file from disk")
    func test_socket_shutdown_removesSocketFile() async throws {
        let path = tempSocketPath()
        let config = UnixSocketConfig(socketPath: path, expectedMode: 0o600, expectedUid: UInt32(geteuid()))
        let server = UnixSocketServer(config: config)
        try await server.start()

        #expect(Foundation.FileManager.default.fileExists(atPath: path), "socket must exist after start")

        await server.shutdown()

        #expect(!Foundation.FileManager.default.fileExists(atPath: path), "socket must be removed after shutdown")
    }

    @Test("TCP-OSC-03: no prior socket file — bind succeeds on clean slate")
    func test_socket_noPriorFile_startSucceeds() async throws {
        let path = tempSocketPath()
        // Verify clean slate (no prior file at path)
        #expect(!Foundation.FileManager.default.fileExists(atPath: path), "precondition: no socket at path before start")

        let config = UnixSocketConfig(socketPath: path, expectedMode: 0o600, expectedUid: UInt32(geteuid()))
        let server = UnixSocketServer(config: config)

        // start() must succeed on a clean path (baseline coverage alongside TCP-OSC-01)
        try await server.start()

        var st = stat()
        #expect(stat(path, &st) == 0, "socket file must exist after start")
        #expect(UInt16(st.st_mode) & 0o777 == 0o600, "mode must be 0600")

        await server.shutdown()
        #expect(!Foundation.FileManager.default.fileExists(atPath: path), "socket file must be removed after shutdown")
    }

    @Test("TCP-OSC-04: sequential start → shutdown → start is idempotent (post-fix recurrence guard)")
    func test_socket_sequentialRestartIsIdempotent() async throws {
        // Codifies the fix for session b5f03eef recurrence: a second start() after
        // shutdown() must not trip EADDRINUSE from the just-removed socket file.
        // See [[brokerd-recovery-full-procedure-2026-06-23]] Stage 4.
        let path = tempSocketPath()
        let config = UnixSocketConfig(socketPath: path, expectedMode: 0o600, expectedUid: UInt32(geteuid()))

        // First boot
        let server = UnixSocketServer(config: config)
        try await server.start()
        #expect(Foundation.FileManager.default.fileExists(atPath: path), "socket must exist after first start")
        await server.shutdown()
        #expect(!Foundation.FileManager.default.fileExists(atPath: path), "socket must be gone after shutdown")

        // Second boot (simulates launchctl kickstart after a crash/rebuild)
        let server2 = UnixSocketServer(config: config)
        do {
            try await server2.start()
        } catch {
            Issue.record("Second start() must succeed after clean shutdown; got \(error)")
            return
        }

        var st = stat()
        #expect(stat(path, &st) == 0, "socket must exist after second start")
        #expect(UInt16(st.st_mode) & 0o777 == 0o600, "mode must be 0600 on second start")

        await server2.shutdown()
    }
}
