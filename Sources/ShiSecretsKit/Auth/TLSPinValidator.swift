import Foundation

// TLSPinValidator — URLSessionDelegate that pins the leaf certificate
// SHA-256 fingerprint of vw.obyw.one.
//
// W1 ships the structural TLS pinning infrastructure. The live pin
// SHA-256 is NOT hardcoded in W1 — the operator injects it during
// W2 manual smoke (see TODO below). Until the pin is configured, all
// valid CA-trusted certificates pass (the default URLSession behavior).
//
// This is an explicit W1 decision: do NOT block the Wave 1 merge on
// procuring the live Vaultwarden leaf certificate fingerprint. W2
// operator smoke is the gate.
//
// TODO(W2 — task #113): Inject real vw.obyw.one leaf cert SHA-256 via
//   ~/.shikki/config.yml `vault.tls_pin_sha256` so the broker can
//   enforce TOFU pinning. Until that key is set, the validator passes
//   any CA-valid certificate. Open task: shi-secrets W2 (#113).
//
// BR-SM-15

/// URLSessionDelegate that performs SHA-256 certificate pinning.
///
/// When `pinnedSHA256` is non-nil, the leaf certificate's DER-encoded
/// SHA-256 digest must match it exactly. A mismatch cancels the connection
/// with `URLError.cancelled`.
///
/// When `pinnedSHA256` is nil (W1 default — pin not yet configured),
/// the default URLSession trust evaluation applies (CA-chain validation).
public final class TLSPinValidator: NSObject, URLSessionDelegate, @unchecked Sendable {

    // MARK: - Properties

    /// SHA-256 hex string of the leaf certificate DER bytes.
    /// `nil` → no pinning; CA trust chain validation only.
    public let pinnedSHA256: String?

    // MARK: - Init

    /// - Parameter pinnedSHA256: Expected SHA-256 hex of the leaf cert.
    ///   Pass `nil` (W1 default) until the operator sets
    ///   `vault.tls_pin_sha256` in config.yml.
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

        // If no pin configured, fall through to CA validation.
        guard let expectedPin = pinnedSHA256 else {
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
