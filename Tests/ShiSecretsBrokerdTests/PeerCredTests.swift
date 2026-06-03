import Foundation
@testable import ShiSecretsBrokerd
import Testing

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

@Suite("PeerCred")
struct PeerCredTests {

    /// Creates a connected socketpair, returning (serverFD, clientFD).
    private func socketPair() -> (Int32, Int32)? {
        var fds = [Int32](repeating: -1, count: 2)
        let streamType = Int32(SOCK_STREAM)
        let result = fds.withUnsafeMutableBufferPointer { ptr -> Int32 in
            socketpair(AF_UNIX, streamType, 0, ptr.baseAddress)
        }
        guard result == 0 else { return nil }
        return (fds[0], fds[1])
    }

    @Test("local caller authenticated via SO_PEERCRED — kernel uid is sole identity")
    func test_localCaller_authenticatedViaSOPEERCRED_kernelUidIsSoleIdentity() throws {
        guard let (server, client) = socketPair() else {
            Issue.record("socketpair failed")
            return
        }
        defer { close(server); close(client) }
        let creds = try peerCredentials(fd: server)
        #expect(creds.uid == UInt32(geteuid()))
    }

    @Test("local caller ignores caller-supplied uid, uses kernel-reported only")
    func test_localCaller_ignoresCallerSuppliedUid_usesOnlyKernelReported() {
        let kernelUid: UInt32 = 1_234
        let spoofed: UInt32 = 999_999
        let trusted = trustedUid(kernelReportedUid: kernelUid, payloadSuppliedUid: spoofed)
        #expect(trusted == kernelUid)
    }

    @Test("peerCredPlatform reports a real, supported platform under test")
    func test_peerCredPlatform_isSupported() {
        let platform = PeerCredPlatform.current
        #expect(platform != .unsupported)
    }
}
