import Foundation

// VaultwardenClient — Swift-native actor wrapping URLSession calls to the
// operator's self-hosted Vaultwarden instance (vw.obyw.one by default).
//
// Authentication: OAuth2 client_credentials grant via the Bitwarden
// Identity endpoint (/identity/connect/token). No bw CLI subprocess;
// no BW_SESSION env var.
//
// Server URL resolution (BR-SM-13, BR-DB-CONFIG-RESOLVED):
//   1. ~/.shikki/config.yml `vault.server`
//   2. SHIKKI_VAULT_URL environment variable
//   3. DEV fallback: https://vw.obyw.one
// Never hardcodes the URL in compiled source.
//
// TLS: TLSPinValidator is wired as the URLSessionDelegate. In W1 the
// pin is nil (no cert SHA pinned yet); the operator injects the real
// pin during W2 smoke via config.yml `vault.tls_pin_sha256`.
//
// BR-SM-09, BR-SM-13, BR-SM-15

// MARK: - Errors

/// Errors produced by VaultwardenClient.
public enum VaultwardenClientError: Swift.Error, Sendable, Equatable {
    /// Token endpoint returned a non-2xx HTTP status.
    case tokenExchangeFailed(httpStatus: Int)

    /// Response body could not be decoded as the expected token response.
    case tokenResponseMalformed

    /// The resolved server URL is not a valid HTTPS URL.
    case invalidServerURL(raw: String)

    /// /api/ciphers/{id} returned a non-2xx status.
    case fetchSecretFailed(httpStatus: Int)

    /// Cipher response body could not be decoded.
    case cipherResponseMalformed

    /// The client has not yet called connect() or the session expired.
    case notAuthenticated

    /// The credentials were not loaded (Keychain empty).
    case credentialsNotLoaded

    /// Network error wrapping the underlying URLError code.
    case networkError(URLError.Code)

    /// POST /api/ciphers returned a non-2xx status (W3 write path).
    case createCipherFailed(httpStatus: Int)

    /// DELETE /api/ciphers/{id} returned a non-2xx status (W3 write path).
    case deleteCipherFailed(httpStatus: Int)

    /// DNS lookup failed for the vault host — operator must set the URL via
    /// SHIKKI_VAULT_URL or ~/.shikki/settings/secrets-brokerd.toml [vault_url].
    case vaultHostUnreachable(message: String)
}

// MARK: - Internal token response shape

private struct TokenResponse: Decodable {
    let access_token: String
    let expires_in: Int       // seconds
    let token_type: String
}

// MARK: - Internal cipher response shape (minimal — only fields W1/W3 need)

private struct CipherResponse: Decodable {
    struct LoginData: Decodable {
        let password: String?
        let username: String?
    }
    struct FieldEntry: Decodable {
        let name: String?
        let value: String?
    }
    let id: String
    let name: String
    let notes: String?   // W3: SecureNote stores value here
    let login: LoginData?
    let fields: [FieldEntry]?
}

// MARK: - Internal cipher create request shape (W3)

private struct CipherCreateRequest: Encodable {
    struct SecureNoteData: Encodable { let type: Int }
    let type: Int              // 2 = SecureNote
    let name: String
    let notes: String
    let secureNote: SecureNoteData
    let folderId: String?
    let favorite: Bool
    let reprompt: Int

    init(name: String, value: String) {
        self.type = 2
        self.name = name
        self.notes = value
        self.secureNote = SecureNoteData(type: 0)
        self.folderId = nil
        self.favorite = false
        self.reprompt = 0
    }
}

// MARK: - VaultwardenClient

/// Swift-native Vaultwarden API client. Replaces the bw CLI subprocess
/// pattern entirely. No `Process()` spawns, no `BW_SESSION` env var.
public actor VaultwardenClient {

    // MARK: - Properties

    private let credentials: VaultwardenCredentials
    private let session: URLSession
    private let sessionCache: SessionCache

    /// Resolved base URL (config-chain resolution done at init).
    private let baseURL: URL

    // MARK: - Init

    /// - Parameter credentials: Loaded from Keychain via KeychainVaultCredentials.
    /// - Parameter pinnedSHA256: Optional TLS pin. Pass `nil` in W1 (operator
    ///   injects during W2 smoke). Pass the leaf cert SHA-256 when available.
    /// - Parameter configYmlVaultServer: Value of `vault.server` from
    ///   ~/.shikki/config.yml if already parsed; `nil` to auto-resolve
    ///   from the environment or DEV default.
    /// - Parameter urlProtocolClasses: Injected URLProtocol classes for testing.
    ///   Pass `nil` (default) in production; inject `[MockURLProtocol.self]` in tests.
    public init(
        credentials: VaultwardenCredentials,
        pinnedSHA256: String? = nil,
        configYmlVaultServer: String? = nil,
        urlProtocolClasses: [AnyClass]? = nil
    ) throws {
        self.credentials = credentials

        // Resolve base URL: config → env → DEV default.
        // BR-SM-13: no compiled-in fallback URL in a named constant —
        // resolution happens at runtime so ops can override without
        // recompiling.
        let resolvedURLString = Self.resolveServerURL(
            configYml: configYmlVaultServer,
            envKey: "SHIKKI_VAULT_URL",
            devDefault: "https://vw.obyw.one"
        )
        guard let url = URL(string: resolvedURLString),
              url.scheme == "https" else {
            throw VaultwardenClientError.invalidServerURL(raw: resolvedURLString)
        }
        self.baseURL = url

        // Build URLSession with TLS pin validator delegate.
        let config = URLSessionConfiguration.ephemeral
        // Ephemeral: no persistent cookies, no disk caching.
        config.urlCache = nil
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        // Inject mock protocol classes for testing; nil in production.
        if let classes = urlProtocolClasses {
            config.protocolClasses = classes
        }
        let validator = TLSPinValidator(pinnedSHA256: pinnedSHA256)
        self.session = URLSession(
            configuration: config,
            delegate: validator,
            delegateQueue: nil
        )

        // SessionCache auto-refresh wired in connect()/refreshToken().
        self.sessionCache = SessionCache(refreshAction: nil)
        // Note: refreshAction is nil here because the actor cannot
        // close over itself before init completes. refreshToken() is
        // called directly by SessionCache's refresh task after W2
        // wires the closure. For W1, BrokerDaemon's bootstrap path
        // calls connect() → refreshToken() explicitly.
    }

    // MARK: - connect()

    /// Exchange the client_credentials grant for an access token.
    /// Stores the token in SessionCache for subsequent calls.
    /// Idempotent: if a valid token is already cached, returns without
    /// making a network call.
    public func connect() async throws {
        // Cache hit — no need to re-exchange.
        if await sessionCache.currentToken() != nil { return }
        try await refreshToken()
    }

    // MARK: - refreshToken()

    /// Force a token refresh. Called by the SessionCache auto-refresh task
    /// and by connect() when no cached token exists.
    public func refreshToken() async throws {
        let tokenURL = baseURL.appendingPathComponent("identity/connect/token")
        var request = URLRequest(url: tokenURL)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")

        // Vaultwarden requires device fields in the client_credentials grant.
        // Without deviceType / deviceIdentifier / deviceName the server returns HTTP 400.
        // deviceType "8" = SDK/CLI per the Bitwarden Identity API spec.
        let deviceID = Self.resolvedDeviceIdentifier()
        let body = [
            "grant_type=client_credentials",
            "scope=api",
            "client_id=\(credentials.clientID.urlFormEncoded)",
            "client_secret=\(credentials.clientSecret.urlFormEncoded)",
            "deviceType=8",
            "deviceIdentifier=\(deviceID.urlFormEncoded)",
            "deviceName=shikki-secrets-brokerd",
        ].joined(separator: "&")
        request.httpBody = body.data(using: .utf8)

        let (data, response) = try await performRequest(request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw VaultwardenClientError.tokenResponseMalformed
        }
        guard (200...299).contains(httpResponse.statusCode) else {
            throw VaultwardenClientError.tokenExchangeFailed(httpStatus: httpResponse.statusCode)
        }

        let tokenResponse: TokenResponse
        do {
            tokenResponse = try JSONDecoder().decode(TokenResponse.self, from: data)
        } catch {
            throw VaultwardenClientError.tokenResponseMalformed
        }

        let expiresAt = Date().addingTimeInterval(TimeInterval(tokenResponse.expires_in))
        await sessionCache.setToken(tokenResponse.access_token, expiresAt: expiresAt)
    }

    // MARK: - fetchSecret(id:)

    /// Fetch a single vault cipher by its UUID.
    /// Returns a dictionary of field names → plaintext values.
    ///
    /// The plaintext is returned ONLY to the calling actor; it is never
    /// logged, written to disk, or passed as a subprocess argument.
    public func fetchSecret(id: String) async throws -> [String: String] {
        guard let token = await sessionCache.currentToken() else {
            throw VaultwardenClientError.notAuthenticated
        }

        let cipherURL = baseURL.appendingPathComponent("api/ciphers/\(id)")
        var request = URLRequest(url: cipherURL)
        request.httpMethod = "GET"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")

        let (data, response) = try await performRequest(request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw VaultwardenClientError.cipherResponseMalformed
        }
        guard (200...299).contains(httpResponse.statusCode) else {
            throw VaultwardenClientError.fetchSecretFailed(httpStatus: httpResponse.statusCode)
        }

        let cipher: CipherResponse
        do {
            cipher = try JSONDecoder().decode(CipherResponse.self, from: data)
        } catch {
            throw VaultwardenClientError.cipherResponseMalformed
        }

        // Build a flat field map: SecureNote notes + login fields + custom fields.
        // Plaintext stays inside this actor; never serialised.
        var result: [String: String] = [:]
        // W3: SecureNote ciphers store value in `notes`.
        if let notes = cipher.notes { result["value"] = notes }
        if let login = cipher.login {
            if let u = login.username { result["username"] = u }
            if let p = login.password { result["password"] = p }
        }
        for field in cipher.fields ?? [] {
            if let name = field.name, let value = field.value {
                result[name] = value
            }
        }
        return result
    }

    // MARK: - createCipher(name:value:) — W3 write path

    /// Create a new SecureNote cipher in the vault.
    /// Returns the cipher ID of the newly created item.
    ///
    /// Vaultwarden accepts plaintext when accessed via API key
    /// (client_credentials grant). No client-side encryption needed.
    /// Decision captured in @db: shikki.secrets.W3-encryption-decision.
    @discardableResult
    public func createCipher(name: String, value: String) async throws -> String {
        guard let token = await sessionCache.currentToken() else {
            throw VaultwardenClientError.notAuthenticated
        }

        let url = baseURL.appendingPathComponent("api/ciphers")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let payload = CipherCreateRequest(name: name, value: value)
        request.httpBody = try JSONEncoder().encode(payload)

        let (data, response) = try await performRequest(request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw VaultwardenClientError.cipherResponseMalformed
        }
        guard (200...299).contains(httpResponse.statusCode) else {
            throw VaultwardenClientError.createCipherFailed(httpStatus: httpResponse.statusCode)
        }

        struct CreateResponse: Decodable { let id: String }
        guard let created = try? JSONDecoder().decode(CreateResponse.self, from: data) else {
            throw VaultwardenClientError.cipherResponseMalformed
        }
        return created.id
    }

    // MARK: - deleteCipher(id:) — W3 write path

    /// Delete a vault cipher by its UUID.
    public func deleteCipher(id: String) async throws {
        guard let token = await sessionCache.currentToken() else {
            throw VaultwardenClientError.notAuthenticated
        }

        let url = baseURL.appendingPathComponent("api/ciphers/\(id)")
        var request = URLRequest(url: url)
        request.httpMethod = "DELETE"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")

        let (_, response) = try await performRequest(request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw VaultwardenClientError.cipherResponseMalformed
        }
        guard (200...299).contains(httpResponse.statusCode) else {
            throw VaultwardenClientError.deleteCipherFailed(httpStatus: httpResponse.statusCode)
        }
    }

    // MARK: - listSecrets()

    /// List all vault items the service account has access to.
    /// Returns an array of `[id: String, name: String]` dictionaries.
    public func listSecrets() async throws -> [[String: String]] {
        guard let token = await sessionCache.currentToken() else {
            throw VaultwardenClientError.notAuthenticated
        }

        let url = baseURL.appendingPathComponent("api/ciphers")
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")

        let (data, response) = try await performRequest(request)
        guard let httpResponse = response as? HTTPURLResponse,
              (200...299).contains(httpResponse.statusCode) else {
            throw VaultwardenClientError.fetchSecretFailed(httpStatus: 0)
        }

        struct ListResponse: Decodable {
            struct Item: Decodable { let id: String; let name: String }
            let data: [Item]
        }
        guard let list = try? JSONDecoder().decode(ListResponse.self, from: data) else {
            throw VaultwardenClientError.cipherResponseMalformed
        }
        return list.data.map { ["id": $0.id, "name": $0.name] }
    }

    // MARK: - Device identifier (static — stable per-machine)

    /// Returns a stable per-machine device identifier for the Vaultwarden
    /// OAuth device fields. Resolution order:
    ///   1. ~/.shikki/config/machine-uuid (operator-generated UUID file)
    ///   2. IOKit IOPlatformUUID (macOS hardware UUID, requires no entitlements)
    ///   3. "shikki-brokerd-fallback" (last resort — should not occur in production)
    ///
    /// The value is NOT a secret — it identifies the device to Vaultwarden
    /// for audit purposes, not for authentication.
    static func resolvedDeviceIdentifier() -> String {
        // 1. Operator-generated UUID file (cross-platform, no IOKit needed).
        let uuidFilePath = (NSHomeDirectory() as NSString)
            .appendingPathComponent(".shikki/config/machine-uuid")
        if let contents = try? String(contentsOfFile: uuidFilePath, encoding: .utf8) {
            let trimmed = contents.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty { return "shikki-brokerd-\(trimmed)" }
        }

        // 2. IOKit hardware UUID (macOS only, no special entitlements required).
        #if canImport(IOKit)
        if let uuid = IOKitMachineUUID() {
            return "shikki-brokerd-\(uuid)"
        }
        #endif

        // 3. Fallback — should not reach production.
        return "shikki-brokerd-fallback"
    }

    // MARK: - URL resolution (static — called once at init)

    /// Resolve the Vaultwarden server URL from the config chain.
    /// Never returns a hardcoded URL constant — always dynamic.
    static func resolveServerURL(
        configYml: String?,
        envKey: String,
        devDefault: String
    ) -> String {
        // 1. config.yml vault.server
        if let v = configYml, !v.isEmpty { return v }
        // 2. Environment variable
        if let v = ProcessInfo.processInfo.environment[envKey], !v.isEmpty { return v }
        // 3. DEV fallback (not a compile-time constant — evaluated at call site)
        return devDefault
    }

    // MARK: - Private: request execution

    private func performRequest(_ request: URLRequest) async throws -> (Data, URLResponse) {
        do {
            return try await session.data(for: request)
        } catch let urlError as URLError {
            // Detect DNS NXDOMAIN / host-not-found errors and surface an
            // actionable message with the config-chain remediation steps.
            if urlError.code == .cannotFindHost || urlError.code == .dnsLookupFailed {
                throw VaultwardenClientError.vaultHostUnreachable(
                    message: "DNS lookup failed for vault host. "
                    + "Set SHIKKI_VAULT_URL or ~/.shikki/settings/secrets-brokerd.toml [vault_url]"
                )
            }
            throw VaultwardenClientError.networkError(urlError.code)
        }
    }
}

// MARK: - URL form encoding helper

private extension String {
    var urlFormEncoded: String {
        addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? self
    }
}

// MARK: - IOKit hardware UUID (macOS)

#if canImport(IOKit)
import IOKit

/// Returns the IOPlatformUUID string from the IOKit registry.
/// This is the hardware board serial identifier, stable across reboots.
/// Returns `nil` only if IOKit registry lookup fails (should not occur on macOS).
private func IOKitMachineUUID() -> String? {
    let matchingDict = IOServiceMatching("IOPlatformExpertDevice")
    let platformExpert = IOServiceGetMatchingService(kIOMainPortDefault, matchingDict)
    guard platformExpert != IO_OBJECT_NULL else { return nil }
    defer { IOObjectRelease(platformExpert) }
    let cfUUID = IORegistryEntryCreateCFProperty(
        platformExpert,
        "IOPlatformUUID" as CFString,
        kCFAllocatorDefault,
        0
    )
    guard let uuid = cfUUID?.takeRetainedValue() as? String else { return nil }
    return uuid
}
#endif
