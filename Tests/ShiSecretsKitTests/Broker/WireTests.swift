import Foundation
@testable import ShiSecretsKit
import Testing

@Suite("Wire (JSON-RPC envelope + framing)")
struct WireTests {

    // MARK: - JSONValue round-trip

    @Test("JSONValue encodes + decodes round-trip for all 7 cases")
    func test_jsonValue_roundTrips_allCases() throws {
        let cases: [JSONValue] = [
            .null,
            .bool(true),
            .bool(false),
            .int(42),
            .int(-7),
            .double(3.14),
            .string("hello"),
            .array([.int(1), .string("a"), .null]),
            .object(["k": .string("v"), "n": .int(5)]),
        ]
        for v in cases {
            let encoded = try JSONEncoder().encode(v)
            let decoded = try JSONDecoder().decode(JSONValue.self, from: encoded)
            #expect(decoded == v, "round-trip lost \(v) → \(decoded)")
        }
    }

    // MARK: - WireRequest

    @Test("WireRequest round-trips with params + id")
    func test_wireRequest_roundTrips() throws {
        let req = WireRequest(
            method: "secret.get",
            params: .object(["scope": .string("openai/api-key")]),
            id: "req-1"
        )
        let data = try encodeWireFrame(req)
        // Frame must end with \n
        #expect(data.last == 0x0A)
        // Strip the newline and decode
        let frame = data.subdata(in: 0..<(data.count - 1))
        let decoded = try decodeWireRequest(frame)
        #expect(decoded == req)
        #expect(decoded.jsonrpc == "2.0")
    }

    @Test("WireRequest with nil id is a notification (still decodes)")
    func test_wireRequest_nilId_isNotification() throws {
        let req = WireRequest(method: "rotate.tick", params: nil, id: nil)
        let frame = try encodeWireFrame(req)
        let parsed = try decodeWireRequest(frame.subdata(in: 0..<(frame.count - 1)))
        #expect(parsed.id == nil)
        #expect(parsed.method == "rotate.tick")
    }

    @Test("WireRequest with wrong jsonrpc version fails decode")
    func test_wireRequest_wrongVersion_failsDecode() throws {
        let badFrame = #"{"jsonrpc":"1.0","method":"secret.get","id":"x"}"#.data(using: .utf8)!
        #expect(throws: DecodingError.self) {
            _ = try decodeWireRequest(badFrame)
        }
    }

    // MARK: - WireResponse

    @Test("WireResponse with result encodes correctly")
    func test_wireResponse_resultVariant() throws {
        let resp = WireResponse(id: "req-1", result: .string("ok"))
        let data = try JSONEncoder().encode(resp)
        let decoded = try JSONDecoder().decode(WireResponse.self, from: data)
        #expect(decoded == resp)
        #expect(decoded.result == .string("ok"))
        #expect(decoded.error == nil)
    }

    @Test("WireResponse with error encodes correctly")
    func test_wireResponse_errorVariant() throws {
        let resp = WireResponse(
            id: "req-1",
            error: WireError(code: WireErrorCode.denied, message: "Caller denied")
        )
        let data = try JSONEncoder().encode(resp)
        let decoded = try JSONDecoder().decode(WireResponse.self, from: data)
        #expect(decoded == resp)
        #expect(decoded.result == nil)
        #expect(decoded.error?.code == WireErrorCode.denied)
    }

    @Test("WireResponse.parseError factory has correct shape")
    func test_wireResponse_parseError_factory() {
        let resp = WireResponse.parseError()
        #expect(resp.id == nil)
        #expect(resp.result == nil)
        #expect(resp.error?.code == WireErrorCode.parseError)
        #expect(resp.error?.message == "Parse error")
    }

    @Test("WireResponse.methodNotFound includes method name in message")
    func test_wireResponse_methodNotFound_factory() {
        let resp = WireResponse.methodNotFound(id: "x", method: "bogus.verb")
        #expect(resp.error?.code == WireErrorCode.methodNotFound)
        #expect(resp.error?.message.contains("bogus.verb") == true)
    }

    // MARK: - Framing

    @Test("encodeWireFrame appends newline terminator")
    func test_framing_appendsNewline() throws {
        let req = WireRequest(method: "x", id: "1")
        let data = try encodeWireFrame(req)
        #expect(data.last == 0x0A)
    }

    @Test("encodeWireFrame rejects oversized payload (BR-WIRE-01)")
    func test_framing_rejectsOversized() {
        // Build a params object exceeding WireMaxFrameSize.
        let bigString = String(repeating: "x", count: WireMaxFrameSize + 100)
        let req = WireRequest(method: "x", params: .string(bigString), id: "1")
        #expect(throws: WireFramingError.self) {
            _ = try encodeWireFrame(req)
        }
    }

    @Test("extractNextFrame splits buffer at first newline")
    func test_framing_extractNext_splits() throws {
        let req1 = try encodeWireFrame(WireRequest(method: "a", id: "1"))
        let req2 = try encodeWireFrame(WireRequest(method: "b", id: "2"))
        var buf = Data()
        buf.append(req1)
        buf.append(req2)
        let (frame, rest) = try #require(extractNextFrame(from: buf))
        // frame should be the first request (no newline)
        let decoded = try decodeWireRequest(frame)
        #expect(decoded.method == "a")
        // Remainder should be the second frame (still has its newline)
        #expect(rest == req2)
    }

    @Test("extractNextFrame returns nil when no terminator yet")
    func test_framing_extractNext_partial_returnsNil() {
        let partial = Data("{\"jsonrpc\":\"2.0\",\"method\":\"x\"".utf8)
        #expect(extractNextFrame(from: partial) == nil)
    }
}
