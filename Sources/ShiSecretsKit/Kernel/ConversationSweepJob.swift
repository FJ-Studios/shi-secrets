import Foundation

// ConversationSweepJob (Task 39 — BR-C-07, BR-E-03).
//
// Two-pronged drain path for the LLM rotation queue:
//   1. warm-qos interval (≤ 900s) periodically drains every active session
//   2. subscribes to SessionEndEvent and drains immediately on close
//
// Either path calls `engine.onConversationEnd(sessionId:)`. The interval
// cap of 15 minutes is BR-C-07 — a hard ceiling so a forgotten session
// (crashed hook) still rotates within one sweep window.

public struct ConversationSweepJob: ShikkiKernelJob {

    /// Hard cap per BR-C-07 — broker CANNOT ship with an interval above this.
    public static let maxSweepIntervalSeconds: TimeInterval = 900

    public let jobId: String = "secrets.conversation.sweep"
    public let qos: QoSTrack = .warm
    public let schedule: Schedule = .interval(ConversationSweepJob.maxSweepIntervalSeconds)

    public let engine: RotationEngine
    public let activeSessions: ActiveSessions

    public init(engine: RotationEngine, activeSessions: ActiveSessions) {
        self.engine = engine
        self.activeSessions = activeSessions
    }

    /// Periodic cron sweep — drains every known session.
    public func run() async throws {
        for sid in await activeSessions.snapshot() {
            try await engine.onConversationEnd(sessionId: sid)
            await activeSessions.remove(sid)
        }
    }

    /// Hook invoked by the EventBus SessionEndEvent subscriber on the
    /// BrokerDaemon. Drains the single session immediately.
    public func onSessionEnd(sessionId: String) async throws {
        try await engine.onConversationEnd(sessionId: sessionId)
        await activeSessions.remove(sessionId)
    }
}

/// Set of currently-active LLM session ids. Populated by the MCP bridge
/// on first `llm_touched=true` call; drained by ConversationSweepJob.
public actor ActiveSessions {
    private var ids: Set<String> = []
    public init() {}

    public func add(_ sid: String) { ids.insert(sid) }
    public func remove(_ sid: String) { ids.remove(sid) }
    public func snapshot() -> [String] { Array(ids).sorted() }
    public func count() -> Int { ids.count }
}
