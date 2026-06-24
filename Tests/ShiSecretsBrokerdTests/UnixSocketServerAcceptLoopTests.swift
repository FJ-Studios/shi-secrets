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

    // =========================================================================
    // Tests for accept-loop spurious-exit fix (backlog 3376CE9152824CCB822E94C3BB9B3EA8)
    // =========================================================================

    // T-06 (Persistence test): accept loop survives 5s of idle — loop is still
    // alive after no connections have arrived.
    //
    // Strategy: start a real bound server + runAcceptLoop in a detached Task.
    // Wait 5s with no connections. Then call requestShutdownAndInterrupt() (the
    // nonisolated interrupt that closes the fd from outside the actor, causing
    // accept() to return EBADF) and verify the loop task completes — i.e. it
    // had not self-terminated before our shutdown signal.
    //
    // Rationale: if the bug were present, the loop would exit immediately after
    // startup (0 iterations) and the loopTask would complete well before the
    // 5s window. We distinguish "clean shutdown" from "spurious exit" by
    // checking the loop was NOT done before we called requestShutdownAndInterrupt().
    //
    // IMPORTANT: uses requestShutdownAndInterrupt() NOT await server.shutdown() —
    // the actor-isolated shutdown() cannot run while accept() is blocking the
    // actor's thread (Phase 0.1 limitation, documented in UnixSocketServer.swift).
    @Test("accept loop survives 5s idle — does not self-terminate without connections")
    func test_acceptLoop_survivesIdleWithoutSelfTerminating() async throws {
        let path = "/tmp/sh-accept-idle-\(UUID().uuidString.prefix(8)).s"
        let config = UnixSocketConfig(socketPath: path, expectedMode: 0o600, expectedUid: UInt32(geteuid()))
        let server = UnixSocketServer(config: config)
        try await server.start()

        actor LoopDone { var done = false; func mark() { done = true } }
        let loopDone = LoopDone()

        let loopTask = Task.detached {
            await server.runAcceptLoop { _, _ in
                WireResponse(id: nil, result: .null)
            }
            await loopDone.mark()
        }

        // Wait 5s — the loop must still be alive (no self-exit).
        try await Task.sleep(nanoseconds: 5_000_000_000)

        // At this point, if the bug were present, loopDone.done == true already.
        let exitedSpontaneously = await loopDone.done
        #expect(!exitedSpontaneously, "accept loop must NOT self-terminate during 5s idle (recurrence #3 regression guard)")

        // Trigger intentional shutdown via the nonisolated interrupt (closes fd
        // from outside the actor, waking the blocked accept() with EBADF).
        server.requestShutdownAndInterrupt()
        loopTask.cancel()
        // Allow the loop to drain (EBADF → return path is synchronous after accept() unblocks).
        try? await Task.sleep(nanoseconds: 500_000_000)
    }

    // T-07 (Multiple sequential connections): the accept loop persists across
    // multiple normal connect/close cycles, proving it does NOT exit after the
    // first successful accept iteration.
    //
    // We connect 5 times sequentially, verify each receives a response, then
    // shutdown cleanly.
    @Test("accept loop persists across multiple sequential connections")
    func test_acceptLoop_persistsAcrossMultipleConnections() async throws {
        let path = "/tmp/sh-accept-multi-\(UUID().uuidString.prefix(8)).s"
        let config = UnixSocketConfig(socketPath: path, expectedMode: 0o600, expectedUid: UInt32(geteuid()))
        let server = UnixSocketServer(config: config)
        try await server.start()

        actor ServedCount { var n = 0; func inc() { n += 1 } }
        let servedCount = ServedCount()

        let loopTask = Task.detached {
            await server.runAcceptLoop { req, _ in
                await servedCount.inc()
                return WireResponse(id: req.id, result: .string("ack"))
            }
        }

        // Helper: open a connection, send one request, read response, close.
        func sendOneRequest(method: String, id: String) throws -> WireResponse? {
            let fd = socket(AF_UNIX, Int32(SOCK_STREAM), 0)
            guard fd >= 0 else { throw POSIXError(.EIO) }
            defer { close(fd) }

            var addr = sockaddr_un()
            addr.sun_family = sa_family_t(AF_UNIX)
            let bytes = Array(path.utf8)
            let cap = MemoryLayout.size(ofValue: addr.sun_path)
            guard bytes.count < cap else { throw POSIXError(.ENAMETOOLONG) }
            withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
                ptr.withMemoryRebound(to: UInt8.self, capacity: cap) { raw in
                    for i in 0 ..< bytes.count { raw[i] = bytes[i] }
                    raw[bytes.count] = 0
                }
            }
            let rc = withUnsafePointer(to: &addr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sp in
                    connect(fd, sp, socklen_t(MemoryLayout<sockaddr_un>.size))
                }
            }
            guard rc == 0 else { throw POSIXError(.ECONNREFUSED) }

            let req = WireRequest(method: method, id: id)
            let data = try encodeWireFrame(req)
            _ = data.withUnsafeBytes { ptr in write(fd, ptr.baseAddress, data.count) }

            // Read response line.
            var buf = Data()
            var byte: UInt8 = 0
            while true {
                let n = read(fd, &byte, 1)
                if n <= 0 { break }
                if byte == 0x0A { break }
                buf.append(byte)
            }
            guard !buf.isEmpty else { return nil }
            return try? JSONDecoder().decode(WireResponse.self, from: buf)
        }

        // Five sequential connections.
        for i in 1...5 {
            // Brief yield so the accept loop can pick up the previous connection.
            try await Task.sleep(nanoseconds: 20_000_000)
            let resp = try sendOneRequest(method: "ping", id: "\(i)")
            #expect(resp != nil, "connection \(i) must receive a response")
            #expect(resp?.id == "\(i)", "response id must match request id for connection \(i)")
        }

        // Allow handlers to finish.
        try await Task.sleep(nanoseconds: 100_000_000)
        let total = await servedCount.n
        #expect(total == 5, "all 5 connections must reach the handler; got \(total)")

        // Use nonisolated interrupt to avoid deadlock with blocked accept().
        server.requestShutdownAndInterrupt()
        loopTask.cancel()
    }

    // T-09 (Idempotent shutdown — R-1 regression guard): calling
    // requestShutdownAndInterrupt() twice must NOT close a recycled fd.
    //
    // The R-1 hazard (panel-rework W1): _listenFdForInterrupt is not cleared after
    // the first call, so a second call fires close() on whatever fd number the OS
    // recycled — silently corrupting an unrelated resource.
    //
    // Detection strategy: after the first requestShutdownAndInterrupt() closes the
    // listen fd, we open a pipe() to grab that fd slot. A sentinel byte is written
    // through the write end. Then we call requestShutdownAndInterrupt() a second time.
    //   - Without the R-1 fix: the second close() kills the pipe read end → read
    //     returns -1 (EBADF) and the sentinel byte is gone.
    //   - After the fix:       second call is a no-op → read returns 1 (sentinel intact).
    @Test("requestShutdownAndInterrupt() is idempotent — second call must NOT close a reused fd (R-1)")
    func test_requestShutdownAndInterrupt_isIdempotent() async throws {
        let path = "/tmp/sh-idem-\(UUID().uuidString.prefix(8)).s"
        let config = UnixSocketConfig(socketPath: path, expectedMode: 0o600, expectedUid: UInt32(geteuid()))
        let server = UnixSocketServer(config: config)
        try await server.start()

        actor LoopDone { var done = false; func mark() { done = true } }
        let loopDone = LoopDone()

        let loopTask = Task.detached {
            await server.runAcceptLoop { _, _ in
                WireResponse(id: nil, result: .null)
            }
            await loopDone.mark()
        }

        // Yield briefly so accept() is actually blocking.
        try await Task.sleep(nanoseconds: 50_000_000)

        // First call — wakes accept loop (listen fd closed → accept() returns EBADF).
        server.requestShutdownAndInterrupt()

        // Wait for the loop to exit.
        try await Task.sleep(nanoseconds: 200_000_000)
        let exitedAfterFirst = await loopDone.done
        #expect(exitedAfterFirst, "accept loop must exit after first requestShutdownAndInterrupt()")

        // Open a pipe to grab whatever fd number was just freed by the first close().
        var pipeEnds: [Int32] = [-1, -1]
        let pipeRc = pipeEnds.withUnsafeMutableBufferPointer { ptr -> Int32 in
            pipe(ptr.baseAddress!)
        }
        guard pipeRc == 0 else {
            Issue.record("could not open pipe for R-1 fd-reuse detection")
            loopTask.cancel()
            return
        }
        let pipeReadFd = pipeEnds[0]
        let pipeWriteFd = pipeEnds[1]
        defer { close(pipeWriteFd) }

        // Write a sentinel byte through the write end before the second interrupt.
        var sentinel: UInt8 = 0xAB
        _ = withUnsafePointer(to: &sentinel) { ptr in
            write(pipeWriteFd, ptr, 1)
        }

        // Second call — must be a no-op.
        // Without the R-1 fix: closes pipeReadFd → subsequent read returns EBADF.
        // With the fix:        _listenFdForInterrupt == -1, no close() fires.
        server.requestShutdownAndInterrupt()

        var readByte: UInt8 = 0
        let n = read(pipeReadFd, &readByte, 1)
        close(pipeReadFd)

        // R-1 assertion: n must be 1 and the byte must be intact.
        #expect(n == 1, "R-1: second requestShutdownAndInterrupt() must NOT close a reused fd; read returned \(n)")
        #expect(readByte == 0xAB, "R-1: sentinel byte must survive; got 0x\(String(readByte, radix: 16))")

        loopTask.cancel()
        try await Task.sleep(nanoseconds: 50_000_000)
    }

    // T-08 (ECONNABORTED is transient): verify that an ECONNABORTED-equivalent
    // reset-before-accept does NOT cause the loop to exit.
    //
    // Direct syscall injection is not possible in pure Swift without a C shim,
    // so we simulate the scenario by opening + immediately RST-closing many
    // connections via SO_LINGER=0. This generates accept() errors on Darwin
    // similar to ECONNABORTED. After the burst, the server must still accept
    // normal connections.
    //
    // Note: on macOS/Darwin, SO_LINGER(0) on AF_UNIX sends an RST-equivalent
    // by closing the socket immediately. The accept loop must survive this.
    @Test("accept loop survives aborted connections and continues serving")
    func test_acceptLoop_survivesAbortedConnections() async throws {
        let path = "/tmp/sh-accept-abrt-\(UUID().uuidString.prefix(8)).s"
        let config = UnixSocketConfig(socketPath: path, expectedMode: 0o600, expectedUid: UInt32(geteuid()))
        let server = UnixSocketServer(config: config)
        try await server.start()

        actor HandledCount { var n = 0; func inc() { n += 1 } }
        let handledCount = HandledCount()

        let loopTask = Task.detached {
            await server.runAcceptLoop { req, _ in
                await handledCount.inc()
                return WireResponse(id: req.id, result: .string("ok"))
            }
        }

        // Helper: connect + immediately abort (SO_LINGER=0 → RST on close).
        func abortConnect() {
            let fd = socket(AF_UNIX, Int32(SOCK_STREAM), 0)
            guard fd >= 0 else { return }
            var addr = sockaddr_un()
            addr.sun_family = sa_family_t(AF_UNIX)
            let bytes = Array(path.utf8)
            let cap = MemoryLayout.size(ofValue: addr.sun_path)
            guard bytes.count < cap else { close(fd); return }
            withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
                ptr.withMemoryRebound(to: UInt8.self, capacity: cap) { raw in
                    for i in 0 ..< bytes.count { raw[i] = bytes[i] }
                    raw[bytes.count] = 0
                }
            }
            _ = withUnsafePointer(to: &addr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sp in
                    connect(fd, sp, socklen_t(MemoryLayout<sockaddr_un>.size))
                }
            }
            // SO_LINGER=0: close sends RST immediately rather than FIN.
            var lg = linger(l_onoff: 1, l_linger: 0)
            _ = withUnsafePointer(to: &lg) { ptr in
                setsockopt(fd, SOL_SOCKET, SO_LINGER, ptr, socklen_t(MemoryLayout<linger>.size))
            }
            close(fd)
        }

        // Fire 8 abort-connects to stress the loop's error handling.
        for _ in 0..<8 {
            abortConnect()
            try await Task.sleep(nanoseconds: 5_000_000)
        }

        // After the aborts, the loop must still be alive. Send a good request.
        try await Task.sleep(nanoseconds: 50_000_000)

        let goodFd = socket(AF_UNIX, Int32(SOCK_STREAM), 0)
        guard goodFd >= 0 else {
            Issue.record("could not create test socket")
            await server.shutdown()
            loopTask.cancel()
            return
        }
        defer { close(goodFd) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        let cap = MemoryLayout.size(ofValue: addr.sun_path)
        guard bytes.count < cap else {
            Issue.record("path too long")
            await server.shutdown()
            loopTask.cancel()
            return
        }
        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            ptr.withMemoryRebound(to: UInt8.self, capacity: cap) { raw in
                for i in 0 ..< bytes.count { raw[i] = bytes[i] }
                raw[bytes.count] = 0
            }
        }
        let rc = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sp in
                connect(goodFd, sp, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        #expect(rc == 0, "good connection must succeed after aborted connections (loop must still be alive)")

        if rc == 0 {
            let req = WireRequest(method: "smoke.check", id: "smoke")
            if let data = try? encodeWireFrame(req) {
                _ = data.withUnsafeBytes { ptr in write(goodFd, ptr.baseAddress, data.count) }
            }
            var buf = Data()
            var byte: UInt8 = 0
            while true {
                let n = read(goodFd, &byte, 1)
                if n <= 0 { break }
                if byte == 0x0A { break }
                buf.append(byte)
            }
            #expect(!buf.isEmpty, "must receive a response after aborted connections")
        }

        // Use nonisolated interrupt to avoid deadlock with blocked accept().
        server.requestShutdownAndInterrupt()
        loopTask.cancel()
    }
}
