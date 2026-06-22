import Foundation
@testable import ShiSecretsBrokerd
import ShiSecretsKit
import Testing

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// Phase 0.1 — Tests for the per-connection serve loop (BR-G-01 + BR-G-02).
//
// Strategy: use `socketpair(2)` to create a connected fd pair without
// going through bind/listen/accept. This isolates the serveConnection
// + framing path from the listen-socket lifecycle and avoids needing
// privileged operations or temp socket-file dance in tests.
//
// CRIT-1 update: serveConnection now takes peerUid + handler takes (WireRequest, UInt32).

@Suite("UnixSocketServer accept loop + wire framer")
struct UnixSocketServerAcceptLoopTests {

    /// Helper: create a connected SOCK_STREAM fd pair.
    private func makeSocketPair() throws -> (clientFd: Int32, serverFd: Int32) {
        var fds: [Int32] = [-1, -1]
        let rc = fds.withUnsafeMutableBufferPointer { ptr -> Int32 in
            socketpair(AF_UNIX, Int32(SOCK_STREAM), 0, ptr.baseAddress)
        }
        guard rc == 0 else {
            throw POSIXError(.EIO)
        }
        return (fds[0], fds[1])
    }

    /// Helper: write a wire frame to a client fd.
    private func writeRawFrame(_ req: WireRequest, to fd: Int32) throws {
        let data = try encodeWireFrame(req)
        try data.withUnsafeBytes { rawPtr in
            var remaining = data.count
            var cursor = rawPtr.baseAddress!
            while remaining > 0 {
                let n = write(fd, cursor, remaining)
                guard n > 0 else { throw POSIXError(.EIO) }
                cursor = cursor.advanced(by: n)
                remaining -= n
            }
        }
    }

    /// Helper: read until newline from a fd.
    private func readFrame(from fd: Int32) -> Data? {
        var buf = Data()
        var byte: UInt8 = 0
        while true {
            let n = read(fd, &byte, 1)
            if n <= 0 { return buf.isEmpty ? nil : buf }
            if byte == 0x0A { return buf }
            buf.append(byte)
        }
    }

    // T-01: serveConnection invokes handler with parsed WireRequest
    @Test("serveConnection dispatches parsed WireRequest to handler")
    func test_serveConnection_dispatchesParsedRequest() async throws {
        let pair = try makeSocketPair()
        defer { close(pair.clientFd) }

        // Capture handler invocations.
        actor Capture {
            var seen: [WireRequest] = []
            var seenUids: [UInt32] = []
            func record(_ r: WireRequest, uid: UInt32) { seen.append(r); seenUids.append(uid) }
        }
        let capture = Capture()
        let testUid = UInt32(geteuid())

        let serveTask = Task.detached {
            await UnixSocketServer.serveConnection(
                clientFd: pair.serverFd,
                peerUid: testUid,
                handler: { req, uid in
                    await capture.record(req, uid: uid)
                    return WireResponse(id: req.id, result: .string("ok"))
                }
            )
        }

        let req = WireRequest(method: "secret.get", params: .object(["scope": .string("openai/api-key")]), id: "r1")
        try writeRawFrame(req, to: pair.clientFd)

        // Read the response from client side.
        let respFrame = readFrame(from: pair.clientFd)
        #expect(respFrame != nil, "expected a response frame back")

        // Close client to terminate serveConnection's read loop.
        close(pair.clientFd)
        await serveTask.value

        let seen = await capture.seen
        #expect(seen.count == 1, "handler should have been invoked once, got \(seen.count)")
        #expect(seen.first?.method == "secret.get")
        #expect(seen.first?.id == "r1")
        // CRIT-1: peerUid threaded correctly into handler.
        #expect(await capture.seenUids.first == testUid, "peerUid must be threaded into handler")
    }

    // T-02: serveConnection writes WireResponse back to client
    @Test("serveConnection writes WireResponse back to client fd")
    func test_serveConnection_writesResponseBack() async throws {
        let pair = try makeSocketPair()
        defer { close(pair.clientFd) }

        let serveTask = Task.detached {
            await UnixSocketServer.serveConnection(
                clientFd: pair.serverFd,
                peerUid: UInt32(geteuid()),
                handler: { req, _ in
                    return WireResponse(id: req.id, result: .string("hello-back"))
                }
            )
        }

        let req = WireRequest(method: "echo.ping", id: "r2")
        try writeRawFrame(req, to: pair.clientFd)

        let respFrame = try #require(readFrame(from: pair.clientFd))
        let resp = try JSONDecoder().decode(WireResponse.self, from: respFrame)
        #expect(resp.id == "r2")
        #expect(resp.result == .string("hello-back"))
        #expect(resp.error == nil)

        close(pair.clientFd)
        await serveTask.value
    }

    // T-03: malformed frame → WireResponse with JSON-RPC parse error
    @Test("malformed frame returns WireResponse parse-error")
    func test_serveConnection_malformedFrame_returnsParseError() async throws {
        let pair = try makeSocketPair()
        defer { close(pair.clientFd) }

        let serveTask = Task.detached {
            await UnixSocketServer.serveConnection(
                clientFd: pair.serverFd,
                peerUid: UInt32(geteuid()),
                handler: { _, _ in
                    return WireResponse(id: nil, result: .null)
                }
            )
        }

        // Garbage bytes + newline
        let garbage = Data("{not valid json}\n".utf8)
        _ = garbage.withUnsafeBytes { ptr in
            write(pair.clientFd, ptr.baseAddress, garbage.count)
        }

        let respFrame = try #require(readFrame(from: pair.clientFd))
        let resp = try JSONDecoder().decode(WireResponse.self, from: respFrame)
        #expect(resp.error?.code == WireErrorCode.parseError)
        #expect(resp.id == nil)

        close(pair.clientFd)
        await serveTask.value
    }

    // T-04: multiple frames on one connection all dispatched
    @Test("serveConnection processes multiple framed requests")
    func test_serveConnection_multipleFrames() async throws {
        let pair = try makeSocketPair()
        defer { close(pair.clientFd) }

        actor Counter {
            var n = 0
            func inc() { n += 1 }
        }
        let counter = Counter()

        let serveTask = Task.detached {
            await UnixSocketServer.serveConnection(
                clientFd: pair.serverFd,
                peerUid: UInt32(geteuid()),
                handler: { req, _ in
                    await counter.inc()
                    return WireResponse(id: req.id, result: .int(Int64(await counter.n)))
                }
            )
        }

        try writeRawFrame(WireRequest(method: "a", id: "1"), to: pair.clientFd)
        try writeRawFrame(WireRequest(method: "b", id: "2"), to: pair.clientFd)
        try writeRawFrame(WireRequest(method: "c", id: "3"), to: pair.clientFd)

        _ = readFrame(from: pair.clientFd)
        _ = readFrame(from: pair.clientFd)
        _ = readFrame(from: pair.clientFd)

        close(pair.clientFd)
        await serveTask.value

        #expect(await counter.n == 3, "expected 3 handler invocations")
    }

    // T-05: EOF (client closes) terminates serveConnection cleanly
    @Test("serveConnection returns when client closes the connection")
    func test_serveConnection_eofTerminatesLoop() async throws {
        let pair = try makeSocketPair()
        // Note: we close clientFd immediately; serveConnection should exit on read=0.

        let serveTask = Task.detached {
            await UnixSocketServer.serveConnection(
                clientFd: pair.serverFd,
                peerUid: UInt32(geteuid()),
                handler: { _, _ in
                    return WireResponse(id: nil, result: .null)
                }
            )
        }
        close(pair.clientFd)

        // serveTask should complete promptly (no hang).
        await withTaskGroup(of: Bool.self) { group in
            group.addTask {
                await serveTask.value
                return true
            }
            group.addTask {
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                return false
            }
            guard let firstResult = await group.next() else { return }
            #expect(firstResult == true, "serveConnection did not terminate within 2s after client close")
            group.cancelAll()
        }
    }
}
