import Foundation

// AnomalySignalListenerJob (Task 38 — BR-C-08).
//
// Subscribes to `shikki.secrets.anomaly` on the EventBus and invokes
// `engine.onAnomaly(_:)` for each payload. Runs at QoS=hot so the <60s
// SLA (BR-C-08) has a chance. Wave 3 delivers a pull-style run() that
// drains a staged queue; Wave 4 will swap to pure event-bus push.

public struct AnomalySignalListenerJob: ShikkiKernelJob {

    public let jobId: String = "secrets.anomaly.listener"
    public let qos: QoSTrack = .hot
    public let schedule: Schedule = .onEvent("shikki.secrets.anomaly")

    public let engine: RotationEngine
    public let staging: AnomalyStaging

    public init(engine: RotationEngine, staging: AnomalyStaging) {
        self.engine = engine
        self.staging = staging
    }

    public func run() async throws {
        for payload in await staging.drainAll() {
            try await engine.onAnomaly(payload.signal, secretName: payload.secretName)
        }
    }
}

/// The event-bus bridge. In Wave 3 tests push payloads directly; Wave 4's
/// MCPBridge + anomaly detectors will push via `AnomalyStaging.push`.
public actor AnomalyStaging {
    public struct Payload: Sendable, Equatable {
        public let signal: AnomalySignal
        public let secretName: String
        public init(signal: AnomalySignal, secretName: String) {
            self.signal = signal
            self.secretName = secretName
        }
    }

    private var queue: [Payload] = []

    public init() {}

    public func push(_ payload: Payload) {
        queue.append(payload)
    }

    public func drainAll() -> [Payload] {
        let out = queue
        queue.removeAll()
        return out
    }

    public func count() -> Int { queue.count }
}
