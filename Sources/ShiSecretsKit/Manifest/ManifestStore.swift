import Foundation

// ManifestStore — holds the currently-pinned MCP manifest and mediates
// startup load + HUP reload.
//
// BR-H-02: verify at startup AND on every reload.
// BR-H-02d: on sig-fail during reload, continue serving the previously
//           pinned manifest (fail-safe, NOT fail-open) and write a
//           `seams.manifestSigFailed` row.
// BR-H-02e: a direct edit to broker schema config without a re-signed
//           manifest is rejected at HUP time — falls under the same
//           fail-safe behavior as any sig-fail.

public actor ManifestStore {

    private let verifier: ManifestVerifier
    private let seams: SeamsWriter
    private var pinned: ManifestVerifier.Manifest?

    public init(verifier: ManifestVerifier, seams: SeamsWriter) {
        self.verifier = verifier
        self.seams = seams
    }

    /// Initial load at broker start. Throws on signature failure — the
    /// broker MUST refuse to start with an unverified manifest (BR-H-02).
    public func loadInitial(bytes: Data, signature: Data) throws {
        let manifest = try verifier.verify(manifestBytes: bytes, signatureBytes: signature)
        pinned = manifest
    }

    /// HUP reload. On sig-fail the previously pinned manifest is kept and
    /// a seams row is appended with signal `manifestSigFailed`.
    public func reload(bytes: Data, signature: Data) async throws {
        do {
            let manifest = try verifier.verify(manifestBytes: bytes, signatureBytes: signature)
            pinned = manifest
        } catch {
            let version = pinned?.version ?? "unpinned"
            try await seams.append(
                signal: .manifestSigFailed(manifestVersion: version),
                secret: "mcp-manifest",
                outcome: .bypassed,
                ts: Date(),
                notes: "manifest reload rejected — keeping pinned \(version)"
            )
            // Do NOT rethrow: BR-H-02d — fail-safe, not fail-open.
        }
    }

    /// Current pinned manifest (nil until `loadInitial` succeeds).
    public func current() -> ManifestVerifier.Manifest? {
        pinned
    }
}
