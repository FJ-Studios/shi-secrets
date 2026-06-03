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
}
