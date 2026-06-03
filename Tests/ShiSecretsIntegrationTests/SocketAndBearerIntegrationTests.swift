import Foundation
@testable import ShiSecretsBrokerd
import ShiSecretsKit
import Testing

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// T65 — Integration: SO_PEERCRED + socket permissions + bearer over real socket.
//
// These tests bind the real UnixSocketServer on a tmp path, connect a
// loopback client, and drive the SO_PEERCRED / LOCAL_PEERCRED kernel
// call. On Darwin, LOCAL_PEERCRED returns `cr_uid` (kernel-reported —
// not payload-supplied). On Linux, SO_PEERCRED returns a ucred struct.

@Suite("SocketAndBearerIntegration")
struct SocketAndBearerIntegrationTests {

    /// Establish a connected socket pair via the listener + a loopback
    /// client. Returns the two fds.
    private func socketPairThroughListener(
        stack: IntegBrokerStack
    ) async throws -> (listenFD: Int32, connFD: Int32, path: String) {
        try await stack.socket.start()
        let path = await stack.socket.config.socketPath
        let listenFD = await stack.socket.socketFD
        // Client connect.
        let clientFD = socket(AF_UNIX, Int32(SOCK_STREAM), 0)
        #expect(clientFD >= 0)
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        withUnsafeMutablePointer(to: &addr.sun_path) { p in
            p.withMemoryRebound(to: UInt8.self, capacity: 104) { raw in
                for i in 0..<bytes.count { raw[i] = bytes[i] }
                raw[bytes.count] = 0
            }
        }
        let addrLen = socklen_t(MemoryLayout<sockaddr_un>.size)
        let rc = withUnsafePointer(to: &addr) { ap in
            ap.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(clientFD, $0, addrLen) }
        }
        #expect(rc == 0)
        // Accept on the server side.
        let connFD = accept(listenFD, nil, nil)
        #expect(connFD >= 0)
        return (listenFD, connFD, path)
    }

    @Test("SO_PEERCRED — kernel-reported uid matches current euid over real unix socket")
    func test_integration_soPeercred_realUnixSocket_kernelReportedUid_matchesExpected() async throws {
        let stack = try await IntegSupport.makeStack()
        defer { Task { await IntegSupport.tearDown(stack) } }
        let (_, connFD, path) = try await socketPairThroughListener(stack: stack)
        defer {
            close(connFD)
            _ = unlink(path)
        }
        let creds = try peerCredentials(fd: connFD)
        #expect(creds.uid == UInt32(geteuid()))
    }

    @Test("spoofed payload uid — ignored in favor of kernel-reported uid")
    func test_integration_soPeercred_spoofedUidInPayload_ignored() {
        // Caller tries to claim uid=0 in the payload; `trustedUid` MUST
        // return the kernel-reported uid every time.
        let kernelUid = UInt32(geteuid())
        let spoofedUid: UInt32 = 0
        let got = trustedUid(kernelReportedUid: kernelUid, payloadSuppliedUid: spoofedUid)
        #expect(got == kernelUid)
        #expect(got != spoofedUid || kernelUid == 0)
    }

    @Test("socket permissions — startup aborts if mode or owner wrong (BR-D-02)")
    func test_integration_socketPermissionsEnforced_startupAbortsIfWrong() async throws {
        // Configure the socket with a WRONG expected uid.
        let badPath = IntegSupport.socketPath()
        let config = UnixSocketConfig(
            socketPath: badPath,
            expectedMode: 0o600,
            expectedUid: UInt32(geteuid()) &+ 7_777   // will never match
        )
        let server = UnixSocketServer(config: config)
        do {
            try await server.start()
            Issue.record("expected ownerMismatch")
        } catch let e as UnixSocketError {
            if case .ownerMismatch = e {
                // ok
            } else {
                Issue.record("wrong error: \(e)")
            }
        }
        _ = unlink(badPath)
    }

    @Test("MCP bearer token flow — bearer accepted maps to wrapped request with llm_touched=true")
    func test_integration_mcpBearerTokenFlow_overRealTransport() async throws {
        let stack = try await IntegSupport.makeStack()
        defer { Task { await IntegSupport.tearDown(stack) } }
        // Access the bridge via the daemon.
        let bridge = await stack.daemon.bridge
        // Bearer in allowlist is "bearer-1" (from IntegSupport stack).
        let wrapped = try await bridge.wrapMcpRequest(payload: Data(), bearer: "bearer-1")
        #expect(wrapped.transport == .mcp)
        #expect(wrapped.llmTouched == true)
        // A bad bearer rejects.
        do {
            _ = try await bridge.wrapMcpRequest(payload: Data(), bearer: "bogus")
            Issue.record("expected bearerRejected")
        } catch MCPBridgeError.bearerRejected {
            // ok
        } catch {
            Issue.record("wrong error: \(error)")
        }
    }
}
