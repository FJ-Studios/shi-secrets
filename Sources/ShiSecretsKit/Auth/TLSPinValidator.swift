import Foundation

// TLSPinValidator — URLSessionDelegate that pins the leaf certificate
// SHA-256 fingerprint of the Vaultwarden server.
//
// W1.5 of spec e8c4a921-7d3b-4f5e-9a2c-1d6b8f4e3a91 — closes task #113.
//
// Pin configuration (priority order):
//   1. SHIKKI_VAULT_TLS_PIN_SHA256 env var (test injection / CI override)
//   2. ~/.shikki/settings/vault.toml key `tls_pin_sha256`
//   3. nil → WARN via os_log + fall back to CA validation
//
// When the pin is configured, the leaf certificate's DER-encoded SHA-256
// digest MUST match it exactly. A mismatch cancels the connection with
// URLError.cancelled. A missing pin emits a WARNING (not an error) to
// preserve brokerd boot-strap before the operator has captured the pin.
//
// TLS 1.3 minimum is enforced at the URLSession level in VaultwardenClient.
// This file handles only the certificate pinning step.
//
// BR-SM-15

#if canImport(os)
import os

private let _pinLog = os.Logger(
    subsystem: "io.shikki.secrets-brokerd",
    category: "vault"
)
#endif

/// URLSessionDelegate that performs SHA-256 certificate pinning.
///
/// When `pinnedSHA256` is non-nil, the leaf certificate's DER-encoded
/// SHA-256 digest must match it exactly. A mismatch cancels the connection
/// with `URLError.cancelled`.
///
/// When `pinnedSHA256` is nil (no pin configured), the validator emits a
/// WARNING via os_log and falls through to standard CA trust evaluation.
public final class TLSPinValidator: NSObject, URLSessionDelegate, @unchecked Sendable {

    // MARK: - Properties

    /// SHA-256 hex string of the leaf certificate DER bytes.
    /// `nil` → no pinning; CA trust chain validation only (with WARN log).
    public let pinnedSHA256: String?

    // MARK: - Factory (load from config chain)

    /// Load the TLS pin from the environment / TOML config chain.
    /// Returns nil if no pin is configured anywhere.
    public static func loadPinnedSHA256(
        homeDirectory: String = NSHomeDirectory()
    ) -> String? {
        // Priority 1: env var (test injection / CI override)
        if let envPin = ProcessInfo.processInfo.environment["SHIKKI_VAULT_TLS_PIN_SHA256"],
           !envPin.isEmpty {
            return envPin
        }
        // Priority 2: ~/.shikki/settings/vault.toml `tls_pin_sha256`
        return readPinFromTOML(homeDirectory: homeDirectory)
    }

    /// Read `tls_pin_sha256` from `~/.shikki/settings/vault.toml`.
    /// Returns nil if the file doesn't exist or the key is absent.
    public static func readPinFromTOML(homeDirectory: String = NSHomeDirectory()) -> String? {
        let tomlPath = (homeDirectory as NSString)
            .appendingPathComponent(".shikki/settings/vault.toml")
        guard let text = try? String(contentsOfFile: tomlPath, encoding: .utf8) else {
            return nil
        }
        return extractTOMLValue(from: text, key: "tls_pin_sha256")
    }

    // MARK: - Init

    /// Direct init with an explicit pin value (or nil for "no pin configured").
    /// Use `TLSPinValidator(pinnedSHA256: TLSPinValidator.loadPinnedSHA256())`
    /// in production to pick up from the config chain.
    public init(pinnedSHA256: String? = nil) {
        self.pinnedSHA256 = pinnedSHA256
    }

    // MARK: - URLSessionDelegate

    public func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod
                == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust
        else {
            // Non-TLS challenge — use default handling.
            completionHandler(.performDefaultHandling, nil)
            return
        }

        // If no pin configured, warn and fall through to CA validation.
        guard let expectedPin = pinnedSHA256 else {
            let host = challenge.protectionSpace.host
            #if canImport(os)
            _pinLog.warning(
                "TLS pin not configured for host=\(host, privacy: .public) — falling back to CA validation. Set tls_pin_sha256 in ~/.shikki/settings/vault.toml"
            )
            #endif
            completionHandler(.performDefaultHandling, nil)
            return
        }

        // Evaluate the trust chain first.
        var error: CFError?
        let trusted = SecTrustEvaluateWithError(serverTrust, &error)
        guard trusted else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // Extract the leaf certificate (index 0) and compute its DER SHA-256.
        guard
            let certChain = SecTrustCopyCertificateChain(serverTrust),
            let leaf = (certChain as? [SecCertificate])?.first
        else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        let derBytes = SecCertificateCopyData(leaf) as Data
        let digest = sha256Hex(derBytes)

        if digest.lowercased() == expectedPin.lowercased() {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            // Pin mismatch — cancel immediately.
            let host = challenge.protectionSpace.host
            #if canImport(os)
            _pinLog.error(
                "TLS pin mismatch for host=\(host, privacy: .public) — connection cancelled (possible MITM)"
            )
            #endif
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

    // MARK: - Private

    private func sha256Hex(_ data: Data) -> String {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { ptr in
            _ = CC_SHA256(ptr.baseAddress, CC_LONG(data.count), &digest)
        }
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - TOML parser (minimal key-value extraction)

    /// Extract a simple key = value pair from TOML text.
    /// Handles quoted values and inline comments.
    static func extractTOMLValue(from text: String, key: String) -> String? {
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty, !line.hasPrefix("#") else { continue }
            guard let eqIdx = line.firstIndex(of: "=") else { continue }
            let lhs = line[..<eqIdx].trimmingCharacters(in: .whitespaces)
            guard lhs == key else { continue }
            var rhs = line[line.index(after: eqIdx)...].trimmingCharacters(in: .whitespaces)
            // Strip surrounding quotes
            if (rhs.hasPrefix("\"") && rhs.hasSuffix("\"")) ||
               (rhs.hasPrefix("'") && rhs.hasSuffix("'")) {
                rhs = String(rhs.dropFirst().dropLast())
            }
            // Strip inline comment (must be after quote-strip)
            if let hashIdx = rhs.firstIndex(of: "#") {
                rhs = rhs[..<hashIdx].trimmingCharacters(in: .whitespaces)
            }
            if !rhs.isEmpty { return rhs }
        }
        return nil
    }
}

// CommonCrypto is available on macOS without an explicit import when
// linking Security.framework. We declare the symbols to avoid
// importing the full module (which requires a bridging header in SPM
// contexts without Swift system module maps on older toolchains).
private typealias CC_LONG = UInt32

@_silgen_name("CC_SHA256")
private func CC_SHA256(
    _ data: UnsafeRawPointer?,
    _ len: CC_LONG,
    _ md: UnsafeMutablePointer<UInt8>?
) -> UnsafeMutablePointer<UInt8>?

private let CC_SHA256_DIGEST_LENGTH: Int32 = 32
