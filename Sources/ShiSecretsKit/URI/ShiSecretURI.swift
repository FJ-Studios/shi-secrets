import Foundation

// ShiSecretURI — parser for the `shi-secret://` URI scheme.
//
// BR-SSEC-01: canonical scheme is `shi-secret://<namespace>/<key>`.
//   - namespace: single-level (no nested slashes), non-empty
//   - key: non-empty
//   - Any other scheme is rejected; `vault://` yields an explicit
//     migration hint per [[secret-refs-via-shi-secrets-broker-not-vault-uri]].
//
// W1 of features/shi-secrets-uri-scheme-and-plugin-extraction-2026-05-31.md.

/// A validated `shi-secret://<namespace>/<key>` URI.
public struct ShiSecretURI: Sendable, Equatable, Hashable, CustomStringConvertible {

    // MARK: - Errors

    public enum ParseError: Swift.Error, Sendable, Equatable, LocalizedError {
        /// The URI uses the legacy `vault://` scheme.
        /// Migrate to `shi-secret://<namespace>/<key>` per
        /// [[secret-refs-via-shi-secrets-broker-not-vault-uri]].
        case legacyVaultScheme(original: String)
        /// The URI scheme is unrecognised (not `shi-secret://`).
        case unsupportedScheme(scheme: String)
        /// The namespace segment is empty.
        case emptyNamespace
        /// The key segment is empty.
        case emptyKey
        /// The namespace contains a slash — namespaces are single-level only.
        case nestedSlashInNamespace(namespace: String)
        /// The raw string could not be parsed as a URI at all.
        case malformedURI(raw: String)

        public var errorDescription: String? {
            switch self {
            case .legacyVaultScheme(let original):
                return "Legacy vault:// URI: \(original) — migrate to shi-secret://<ns>/<key> per [[secret-refs-via-shi-secrets-broker-not-vault-uri]]."
            case .unsupportedScheme(let scheme):
                return "Unsupported URI scheme '\(scheme)'; expected 'shi-secret'."
            case .emptyNamespace:
                return "shi-secret:// URI has an empty namespace segment."
            case .emptyKey:
                return "shi-secret:// URI has an empty key segment."
            case .nestedSlashInNamespace(let ns):
                return "Namespace '\(ns)' contains a slash — namespaces are single-level."
            case .malformedURI(let raw):
                return "Could not parse '\(raw)' as a URI."
            }
        }
    }

    // MARK: - Properties

    /// The namespace segment, e.g. `obyw`.
    public let namespace: String

    /// The key segment, e.g. `pb-admin`.
    public let key: String

    // MARK: - Derived

    /// Full URI string, e.g. `shi-secret://obyw/pb-admin`.
    public var description: String { "shi-secret://\(namespace)/\(key)" }

    /// Qualified key in `<namespace>/<key>` form, suitable for backend lookup.
    public var qualifiedKey: String { "\(namespace)/\(key)" }

    // MARK: - Parsing

    /// Parses a raw string into a validated `ShiSecretURI`.
    ///
    /// - Throws: `ParseError` if the string is not a valid `shi-secret://` URI.
    public static func parse(_ raw: String) throws -> ShiSecretURI {
        // Fast-path rejection for the legacy scheme with an explicit migration hint.
        if raw.hasPrefix("vault://") {
            throw ParseError.legacyVaultScheme(original: raw)
        }

        // Ensure the scheme is exactly `shi-secret`.
        guard raw.hasPrefix("shi-secret://") else {
            let scheme: String
            if let colonRange = raw.range(of: "://") {
                scheme = String(raw[raw.startIndex..<colonRange.lowerBound])
            } else {
                scheme = raw
            }
            throw ParseError.unsupportedScheme(scheme: scheme)
        }

        // Strip the scheme prefix to get `<namespace>/<key>`.
        let rest = String(raw.dropFirst("shi-secret://".count))

        // Require exactly one slash separating namespace from key.
        guard let slashIdx = rest.firstIndex(of: "/") else {
            if rest.isEmpty {
                throw ParseError.emptyNamespace
            }
            throw ParseError.emptyKey
        }

        let namespace = String(rest[rest.startIndex..<slashIdx])
        let key = String(rest[rest.index(after: slashIdx)...])

        if namespace.isEmpty {
            throw ParseError.emptyNamespace
        }
        // Namespace must not contain additional slashes (single-level only).
        if namespace.contains("/") {
            throw ParseError.nestedSlashInNamespace(namespace: namespace)
        }
        if key.isEmpty {
            throw ParseError.emptyKey
        }

        return ShiSecretURI(namespace: namespace, key: key)
    }

    // MARK: - Private init

    private init(namespace: String, key: String) {
        self.namespace = namespace
        self.key = key
    }
}
