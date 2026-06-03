import Foundation

// AnomalySignal — the rotation engine's incoming alarm surface.
//
// Anomaly-driven rotations override dormancy, cadence, and queued state and
// must execute within 60s of signal receipt (BR-C-08). The broker appends
// exactly one `seams` row per anomaly-driven rotation (BR-G-03) carrying the
// signal's tag. Each case carries only the fields needed by the rotation
// engine — never plaintext, never token bytes.

public enum AnomalySignal: Sendable, Codable, Equatable {
    /// HaveIBeenPwned email / breach advisory hit.
    case hibp(breachId: String)
    /// A fetch originated from an IP that was not in the entry's expected set.
    case unexpectedIP(ip: String, secretName: String)
    /// N consecutive failed fetches within a short window (scraping attempt).
    case failedFetchBurst(windowSec: Int, count: Int, secretName: String)
    /// Vendor-side advisory (e.g. GitHub token leak feed).
    case vendorBreach(vendor: String, advisoryURL: String)
    /// A self-revoking discovery token did not invoke its documented
    /// self-revoke call before dies_at (BR-E-06).
    case selfRevokeMissed(jti: String, secretName: String)
    /// MCP manifest signature verification failed on startup or HUP (BR-H-02d).
    case manifestSigFailed(manifestVersion: String)
    /// No rotation driver was registered for the entry's vendor scope.
    /// Review finding #7 — surfaces the fallback visibly instead of
    /// silently returning `.failed`.
    case noDriverRegistered(vendor: String, secretName: String)
    /// Review finding U10 — the LLM rotation queue hit its per-session
    /// or global cap and dropped the oldest session. Surfaces as a seam
    /// row so ops can detect an MCP caller spraying secret names.
    case llmQueueSaturated(sessionId: String, droppedCount: Int)
    /// 3rd-pass validator I2 — `compensateRevoke` ran after a persist
    /// failure BUT the jti was never actually inserted (persist failed
    /// before the row was written). The helper no longer silently
    /// swallows the resulting `.invalidJti`; this seam surfaces the
    /// no-op so ops can correlate the over-audited allow row with a
    /// deliberately skipped revoke.
    case persistCompensationNoOp(scope: String)
    /// 3rd-pass validator I2 — `compensateRevoke` ran after a persist
    /// failure AND the revoke itself threw an UNexpected error (i.e.
    /// not `.invalidJti`). Carries the error description so ops can
    /// triage instead of hunting through logs.
    case persistCompensationFailed(scope: String, error: String)
    /// 3rd-pass validator T4 — `RotationTickJob.handleFailure` itself
    /// threw inside the tick's failure branch. Previously this bolted
    /// onto `.failedFetchBurst(windowSec: 0, count: 0, ...)`; the
    /// dedicated case makes the double-failure surface diagnostic.
    case rotationHandlerDoubleFailure(secretName: String, primary: String, secondary: String)
    /// Item #9 — a passkey-signed admin action (currently
    /// `revokeAllBots`) successfully verified and was carried out by
    /// the broker. Carries the operator's audit actor + the envelope
    /// nonce so post-incident review can correlate the seam with the
    /// signing ceremony log. NEVER carries signature bytes.
    case adminActionExecuted(action: String, actor: String, nonce: String)
}
