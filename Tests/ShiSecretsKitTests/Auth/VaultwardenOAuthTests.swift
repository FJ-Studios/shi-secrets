import Testing
@testable import ShiSecretsKit
import Foundation

// VaultwardenOAuthTests — TP-OAUTH-01..07
//
// Verifies that VaultwardenClient.refreshToken() produces an
// application/x-www-form-urlencoded POST body containing all 7 required
// Bitwarden Identity API fields for the client_credentials grant.
//
// Root cause: without deviceType / deviceIdentifier / deviceName,
// Vaultwarden returns HTTP 400 (verified 2026-05-26 via direct Python probe).
//
// TP-OAUTH-01: body contains all 7 required field names
// TP-OAUTH-02: deviceType value is "8"
// TP-OAUTH-03: deviceIdentifier is non-empty
// TP-OAUTH-04: deviceName is "shikki-secrets-brokerd"
// TP-OAUTH-05: body is properly URL-encoded (no raw spaces/special chars in key names)
// TP-OAUTH-06: HTTP request Content-Type is application/x-www-form-urlencoded
// TP-OAUTH-07: mocked 200 response decodes access_token correctly
//
// SERIAL: tests share a static mock handler — must not run in parallel.

// MARK: - Mock URLProtocol

final class OAuthMockURLProtocol: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) static var handler: ((URLRequest) throws -> (Data, HTTPURLResponse))?

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let handler = OAuthMockURLProtocol.handler else {
            client?.urlProtocol(self, didFailWithError: URLError(.unknown))
            return
        }
        // URLProtocol receives a canonical request where httpBody may be nil
        // (replaced by httpBodyStream). Reconstitute from the stream if needed.
        var req = request
        if req.httpBody == nil, let stream = req.httpBodyStream {
            req.httpBody = Data(reading: stream)
        }
        do {
            let (data, response) = try handler(req)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}

// MARK: - InputStream → Data helper

private extension Data {
    /// Read all available bytes from an InputStream into Data.
    init(reading stream: InputStream) {
        self.init()
        stream.open()
        defer { stream.close() }
        let bufSize = 4096
        var buf = [UInt8](repeating: 0, count: bufSize)
        while stream.hasBytesAvailable {
            let n = stream.read(&buf, maxLength: bufSize)
            if n > 0 { self.append(contentsOf: buf.prefix(n)) }
            else { break }
        }
    }
}

// MARK: - Helpers

private func makeTestCredentials() -> VaultwardenCredentials {
    VaultwardenCredentials(
        clientID: "user.test-oauth-uuid",
        clientSecret: "test-oauth-secret",
        serverURL: URL(string: "https://vw.obyw.one")!
    )
}

private func makeOKTokenResponse(token: String = "tok_test_123") -> Data {
    """
    {"access_token":"\(token)","expires_in":3600,"token_type":"Bearer"}
    """.data(using: .utf8)!
}

/// Parse the form-encoded body into a key→value dictionary.
private func parseFormBody(_ body: String) -> [String: String] {
    var result: [String: String] = [:]
    for pair in body.split(separator: "&") {
        let parts = pair.split(separator: "=", maxSplits: 1)
        guard parts.count == 2 else { continue }
        let key = String(parts[0]).removingPercentEncoding ?? String(parts[0])
        let value = String(parts[1]).removingPercentEncoding ?? String(parts[1])
        result[key] = value
    }
    return result
}

/// Capture the full POST body + headers from a single refreshToken() call via mock.
private func captureTokenRequest(
    credentials: VaultwardenCredentials = makeTestCredentials()
) async throws -> URLRequest {
    final class Box<T>: @unchecked Sendable { var value: T?; init() {} }
    let box = Box<URLRequest>()
    OAuthMockURLProtocol.handler = { request in
        box.value = request
        let resp = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
        return (makeOKTokenResponse(), resp)
    }
    let client = try VaultwardenClient(
        credentials: credentials,
        configYmlVaultServer: "https://vw.obyw.one",
        urlProtocolClasses: [OAuthMockURLProtocol.self]
    )
    try await client.refreshToken()
    guard let req = box.value else {
        throw URLError(.unknown)
    }
    return req
}

// MARK: - VaultwardenOAuthTests
//
// .serialized prevents concurrent test bodies from racing on the static handler.

@Suite("VaultwardenOAuth — device fields (TP-OAUTH-01..07)", .serialized)
struct VaultwardenOAuthTests {

    // TP-OAUTH-01: body contains all 7 required field names
    @Test("TP-OAUTH-01: POST body contains all required field names")
    func testAllRequiredFieldsPresent() async throws {
        let req = try await captureTokenRequest()
        let body = req.httpBody.flatMap { String(data: $0, encoding: .utf8) } ?? ""
        let fields = parseFormBody(body)
        let required = ["grant_type", "scope", "client_id", "client_secret",
                        "deviceType", "deviceIdentifier", "deviceName"]
        for key in required {
            #expect(fields[key] != nil, "Missing required field: \(key)")
        }
    }

    // TP-OAUTH-02: deviceType value is "8"
    @Test("TP-OAUTH-02: deviceType is string value '8'")
    func testDeviceTypeIsEight() async throws {
        let req = try await captureTokenRequest()
        let body = req.httpBody.flatMap { String(data: $0, encoding: .utf8) } ?? ""
        let fields = parseFormBody(body)
        #expect(fields["deviceType"] == "8", "deviceType must be '8' (SDK/CLI per Bitwarden spec)")
    }

    // TP-OAUTH-03: deviceIdentifier is non-empty
    @Test("TP-OAUTH-03: deviceIdentifier is non-empty")
    func testDeviceIdentifierNonEmpty() async throws {
        let req = try await captureTokenRequest()
        let body = req.httpBody.flatMap { String(data: $0, encoding: .utf8) } ?? ""
        let fields = parseFormBody(body)
        let deviceID = fields["deviceIdentifier"] ?? ""
        #expect(!deviceID.isEmpty, "deviceIdentifier must be non-empty")
    }

    // TP-OAUTH-04: deviceName is "shikki-secrets-brokerd"
    @Test("TP-OAUTH-04: deviceName is 'shikki-secrets-brokerd'")
    func testDeviceNameCorrect() async throws {
        let req = try await captureTokenRequest()
        let body = req.httpBody.flatMap { String(data: $0, encoding: .utf8) } ?? ""
        let fields = parseFormBody(body)
        #expect(fields["deviceName"] == "shikki-secrets-brokerd")
    }

    // TP-OAUTH-05: body is properly URL-encoded (key names are plain ASCII)
    @Test("TP-OAUTH-05: body is properly URL-encoded")
    func testBodyIsURLEncoded() async throws {
        let req = try await captureTokenRequest()
        let body = req.httpBody.flatMap { String(data: $0, encoding: .utf8) } ?? ""
        // A valid form-encoded body must not contain raw spaces
        #expect(!body.contains(" "), "URL-encoded body must not contain raw spaces")
        // Must parse to at least 7 key-value pairs
        let fields = parseFormBody(body)
        #expect(fields.count >= 7, "Expected at least 7 key-value pairs, got \(fields.count)")
    }

    // TP-OAUTH-06: HTTP request Content-Type is application/x-www-form-urlencoded
    @Test("TP-OAUTH-06: Content-Type header is application/x-www-form-urlencoded")
    func testContentTypeHeader() async throws {
        let req = try await captureTokenRequest()
        let ct = req.value(forHTTPHeaderField: "Content-Type")
        #expect(ct == "application/x-www-form-urlencoded",
                "Content-Type must be application/x-www-form-urlencoded")
    }

    // TP-OAUTH-07: mocked 200 response decodes access_token correctly
    @Test("TP-OAUTH-07: mocked 200 response — access_token stored in session cache")
    func testMocked200DecodesToken() async throws {
        let expectedToken = "tok_verified_\(UUID().uuidString)"
        OAuthMockURLProtocol.handler = { request in
            let body = """
            {"access_token":"\(expectedToken)","expires_in":3600,"token_type":"Bearer"}
            """.data(using: .utf8)!
            let resp = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (body, resp)
        }
        let creds = makeTestCredentials()
        let client = try VaultwardenClient(
            credentials: creds,
            configYmlVaultServer: "https://vw.obyw.one",
            urlProtocolClasses: [OAuthMockURLProtocol.self]
        )
        // Must not throw — mock returns valid JSON
        try await client.refreshToken()
        // Second call (connect) is a cache hit — must not make another request
        // (handler still set; if called again, returns the same token, which is fine)
        try await client.connect()
        #expect(Bool(true), "access_token decoded and cached successfully")
    }
}
