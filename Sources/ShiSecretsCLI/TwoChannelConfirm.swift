import Foundation
import ShiSecretsKit
import ShiSecretsClient

// TwoChannelConfirm — `shi secret rotate` confirmation surface (T59 — BR-B-03).
//
// On successful rotation the CLI renders a *terminal fingerprint pair*
// (old jti 4-char suffix + wall-clock invalidation time) and fires two
// out-of-band notifications:
//
//   1. Mattermost post   — daily chat stream
//   2. ntfy push         — mobile / desktop OS-native notification
//
// Both notifications carry a 5-minute `/undo` link. Real HTTP posts are
// Wave 5 integration-test territory (mocked against a recording server);
// the CLI layer uses a `ConfirmationChannel` protocol so tests can assert
// both calls happen with the right payload.

public protocol ConfirmationChannel: Sendable {
    var name: String { get }
    func post(message: String, undoLink: String) async throws
}

public actor RecordingConfirmationChannel: ConfirmationChannel {
    public let name: String
    public private(set) var posted: [(message: String, undoLink: String)] = []
    public init(name: String) { self.name = name }
    public func post(message: String, undoLink: String) async throws {
        posted.append((message, undoLink))
    }
    public func snapshot() -> [(message: String, undoLink: String)] { posted }
}

public enum TwoChannelConfirm {

    /// Terminal fingerprint pair — rendered to stdout on successful
    /// rotation. Deterministic format so snapshot tests pin it.
    ///
    /// Review finding #10 — format the wall-clock time in the actual
    /// target timezone rather than UTC. Previous code rendered UTC then
    /// slapped a "CET" label on top, which misled operators running the
    /// confirmation in a non-UTC locale.
    public static func renderTerminalPair(for result: RotationResult, timeZone: String) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        // Map the caller-supplied label to a real TZ identifier. "CET"
        // stays aliased to `Europe/Paris` (the broker's operator locale)
        // because macOS' TimeZone(abbreviation:) does not resolve DST
        // correctly for a bare "CET" abbreviation.
        let identifier: String
        switch timeZone.uppercased() {
        case "CET", "CEST", "EUROPE/PARIS":
            identifier = "Europe/Paris"
        default:
            identifier = timeZone
        }
        formatter.timeZone = TimeZone(identifier: identifier)
            ?? TimeZone(abbreviation: timeZone)
            ?? TimeZone(identifier: "Europe/Paris")
            ?? .current
        formatter.dateFormat = "HH:mm:ss"
        let hhmmss = formatter.string(from: result.invalidAt)
        return "rotated \(result.secretName) (old …\(result.oldJtiSuffix) invalid since \(hhmmss) \(timeZone))"
    }

    /// Fan-out posts to both channels (BR-B-03). Returns the rendered
    /// message + undo link for the caller to print on stderr.
    @discardableResult
    public static func fanout(
        result: RotationResult,
        channels: [any ConfirmationChannel],
        undoTTL: TimeInterval = 300
    ) async throws -> (message: String, undoLink: String) {
        let msg = "shikki: rotated \(result.secretName) — reborn as new jti; old …\(result.oldJtiSuffix) invalid"
        let undo = "/undo/\(result.secretName)?ttl=\(Int(undoTTL))"
        for ch in channels {
            try await ch.post(message: msg, undoLink: undo)
        }
        return (msg, undo)
    }
}
