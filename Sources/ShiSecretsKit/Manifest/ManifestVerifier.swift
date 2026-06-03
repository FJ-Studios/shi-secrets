import Crypto
import Foundation

// ManifestVerifier — pins an Ed25519 public key at provisioning time and
// verifies `mcp-manifest.json` payloads against `mcp-manifest.json.sig`
// (BR-H-02a, BR-H-02b). The broker NEVER possesses the private key; it
// lives behind the Daimyo's passkey and is used only by the external
// signing tool `shikki-manifest-sign`.
//
// The manifest itself is a JSON document with the shape:
//   { version, issued_at, tools: [ ToolEntry ] }
// Each ToolEntry locks a `tool_name`, `schema_hash`, `scope_glob`,
// `max_ttl`, and required `op` so the broker can enforce BR-H-05
// (reject any request whose `op` does not match the invoked tool's
// signed schema).

public struct ManifestVerifier: Sendable {

    public enum VerifyError: Swift.Error, Sendable, Equatable {
        case signatureMismatch
        case decodeFailed(String)
    }

    public struct ToolEntry: Codable, Sendable, Equatable {
        public let toolName: String
        public let schemaHash: String
        public let scopeGlob: String
        public let maxTtl: Int
        public let op: ShikkiSBT.Op

        enum CodingKeys: String, CodingKey {
            case toolName   = "tool_name"
            case schemaHash = "schema_hash"
            case scopeGlob  = "scope_glob"
            case maxTtl     = "max_ttl"
            case op
        }

        public init(
            toolName: String,
            schemaHash: String,
            scopeGlob: String,
            maxTtl: Int,
            op: ShikkiSBT.Op
        ) {
            self.toolName = toolName
            self.schemaHash = schemaHash
            self.scopeGlob = scopeGlob
            self.maxTtl = maxTtl
            self.op = op
        }
    }

    public struct Manifest: Codable, Sendable, Equatable {
        public let version: String
        public let issuedAt: Date
        public let tools: [ToolEntry]

        enum CodingKeys: String, CodingKey {
            case version
            case issuedAt = "issued_at"
            case tools
        }

        public init(version: String, issuedAt: Date, tools: [ToolEntry]) {
            self.version = version
            self.issuedAt = issuedAt
            self.tools = tools
        }
    }

    public let pinnedPublicKey: Curve25519.Signing.PublicKey

    public init(pinnedPublicKey: Curve25519.Signing.PublicKey) {
        self.pinnedPublicKey = pinnedPublicKey
    }

    /// Verifies `manifestBytes` against `signatureBytes` using the pinned
    /// public key, then decodes the manifest JSON. Throws
    /// `.signatureMismatch` on cryptographic failure, `.decodeFailed` on
    /// schema failure.
    public func verify(manifestBytes: Data, signatureBytes: Data) throws -> Manifest {
        guard pinnedPublicKey.isValidSignature(signatureBytes, for: manifestBytes) else {
            throw VerifyError.signatureMismatch
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        do {
            return try decoder.decode(Manifest.self, from: manifestBytes)
        } catch {
            throw VerifyError.decodeFailed(String(describing: error))
        }
    }
}
