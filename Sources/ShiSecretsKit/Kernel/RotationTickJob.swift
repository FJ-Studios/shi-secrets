import Foundation

// RotationTickJob — one per tier × QoS-track (Task 37 — BR-C-0X).
//
// The kernel fires each track at its declared interval; the job thin-wraps
// `engine.tick(track:)` and, for each due secret name, invokes the vendor
// driver + `applyRotation` / `handleFailure`. Full driver dispatch is
// Wave 4 (T42-T46); Wave 3 ships the tick dispatch shape so the DI wiring
// (T41) + kernel registration (Wave 4 T53) can be exercised.

public struct RotationTickJob: ShikkiKernelJob {

    public let track: QoSTrackTier
    public let engine: RotationEngine

    public init(track: QoSTrackTier, engine: RotationEngine) {
        self.track = track
        self.engine = engine
    }

    /// Kernel entrypoint. Enumerates candidates for the track and
    /// dispatches each through the engine. Errors from individual
    /// entries are caught so one bad vendor doesn't take down the
    /// tick — the engine audits each failure row, and a failure in the
    /// audit-of-failure itself now surfaces as a seam (review finding
    /// U20 — `try?` was hiding a double-failure path).
    public func run() async throws {
        let candidates = await engine.tick(track: track)
        for name in candidates {
            guard let entry = await engine.entry(name: name) else { continue }
            // Minimal dispatch: try to apply rotation directly. Real
            // vendor round-trip is Wave 4; in Wave 3 the engine's
            // internal driver registry handles the call.
            do {
                _ = try await engine.applyRotation(entry: entry)
            } catch let applyError {
                // Surface the failure-of-failure via the engine's seam
                // writer so an operator can see a rotation-handling
                // chain broken at the audit layer.
                do {
                    try await engine.handleFailure(entry: entry, reason: String(describing: applyError))
                } catch let doubleFail {
                    await engine.seamRotationHandlerDoubleFailure(
                        secretName: entry.name,
                        primary: String(describing: applyError),
                        secondary: String(describing: doubleFail)
                    )
                }
            }
        }
    }

    /// The kernel-registered id for this job.
    public var jobId: String { "secrets.rotation.\(track.rawValue)" }

    /// The QoS track this job occupies on the kernel.
    public var qos: QoSTrack {
        switch track {
        case .hot:      return .hot
        case .warm:     return .warm
        case .cool:     return .cool
        case .external: return .external
        }
    }

    /// The tick interval for this track, locked in
    /// `features/shikki-secrets-broker.md` Phase 3 §4:
    ///   hot=300s, warm=1800s, cool=7200s, external=21600s.
    public var schedule: Schedule {
        switch track {
        case .hot:      return .interval(300)
        case .warm:     return .interval(1800)
        case .cool:     return .interval(7200)
        case .external: return .interval(21600)
        }
    }
}
