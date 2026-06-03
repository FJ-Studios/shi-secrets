import Crypto
import Foundation

// EntitlementConfig — maps every caller identity (local uid or MCP
// bearer) to a set of glob scopes. Loaded at broker startup from a
// signed JSON payload (Ed25519 signature verified against a pinned
// public key). Runtime mutation without a re-signed payload is
// rejected (BR-D-07).
//
// The config is a value type. Once loaded, `lookup(uidOrBearer:)`
// returns the glob set for the caller; an absent caller yields the
// empty set (handler translates that into `scope_denied`, BR-D-06).

public struct EntitlementConfig: Sendable, Codable, Equatable {

    public enum LoadError: Swift.Error, Sendable, Equatable {
        case signatureMismatch
        case decodeFailed(String)
    }

    public struct Binding: Sendable, Codable, Equatable {
        public let caller: String   // "uid:1001" or "bearer:<name>"
        public let globs: [String]

        public init(caller: String, globs: [String]) {
            self.caller = caller
            self.globs = globs
        }
    }

    public struct Payload: Sendable, Codable, Equatable {
        public let bindings: [Binding]

        public init(bindings: [Binding]) {
            self.bindings = bindings
        }
    }

    public let payload: Payload

    public init(payload: Payload) {
        self.payload = payload
    }

    /// Verifies `bytes` with `signature` under `pub`, then decodes the
    /// payload. Any tamper between signing and load throws
    /// `signatureMismatch` (BR-D-07 enforcement).
    public static func loadSigned(
        bytes: Data,
        signature: Data,
        pub: Curve25519.Signing.PublicKey
    ) throws -> EntitlementConfig {
        guard pub.isValidSignature(signature, for: bytes) else {
            throw LoadError.signatureMismatch
        }
        do {
            let payload = try JSONDecoder().decode(Payload.self, from: bytes)
            return EntitlementConfig(payload: payload)
        } catch {
            throw LoadError.decodeFailed(String(describing: error))
        }
    }

    /// Returns the glob set for the caller identity string, or an empty
    /// array if the caller is not entitled. The handler maps an empty
    /// result into a `scope_denied` deny row.
    public func lookup(uidOrBearer: String) -> [String] {
        payload.bindings.first(where: { $0.caller == uidOrBearer })?.globs ?? []
    }

    /// Convenience: ALL globs across every binding, used when building
    /// the ScopeValidator's server-side allowlist.
    public var globs: [String] {
        var seen = Set<String>()
        var result: [String] = []
        for binding in payload.bindings {
            for glob in binding.globs where !seen.contains(glob) {
                seen.insert(glob)
                result.append(glob)
            }
        }
        return result
    }
}
