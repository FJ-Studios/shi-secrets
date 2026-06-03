import Foundation

// SessionCache — actor-isolated in-memory store for the short-lived
// Vaultwarden access token.
//
// Security invariants (BR-SM-12):
//   - The token string NEVER leaves this actor as a plain value except
//     via the single `currentToken()` method.
//   - The token is NEVER written to disk, logged, or passed as a
//     subprocess argument.
//   - When `invalidate()` is called, the in-memory bytes are wiped
//     immediately (var replaced with nil, not just flag-flipped).
//
// Auto-refresh (BR-SM-10, BR-SM-11):
//   - A Task is spawned when a new token is set; it fires 60s before
//     the token expires and calls the injected refresh closure.
//   - On refresh failure, exponential backoff is applied starting at 5s,
//     capping at 60s, up to 5 consecutive failures before the cache
//     enters the `.error` state (BR-SM-11).
//
// The refresh closure is injected at construction so the actor can be
// unit-tested without a live Vaultwarden instance.

/// Actor-isolated cache for the broker's current Vaultwarden access token.
public actor SessionCache {

    // MARK: - Constants

    /// How many seconds before expiry to trigger a proactive refresh.
    static let refreshLeadSeconds: TimeInterval = 60

    /// Initial backoff delay on refresh failure.
    static let initialBackoffSeconds: TimeInterval = 5

    /// Maximum backoff delay on refresh failure.
    static let maxBackoffSeconds: TimeInterval = 60

    /// Number of consecutive failures before entering error state.
    static let maxConsecutiveFailures: Int = 5

    // MARK: - State

    private var token: String?
    private var expiresAt: Date?
    private var consecutiveFailures: Int = 0
    private var refreshTask: Task<Void, Never>?

    /// Injected refresh closure. Called by the auto-refresh task.
    /// Returns a new (token, expiresAt) pair or throws on failure.
    public typealias RefreshAction = @Sendable () async throws -> (token: String, expiresAt: Date)
    private let refreshAction: RefreshAction?

    /// Current session state. Used by BrokerDaemon to gate mint requests.
    public private(set) var state: SessionState = .locked

    // MARK: - Init

    /// - Parameter refreshAction: Closure called by the auto-refresh task.
    ///   Pass `nil` in unit tests that drive the cache directly without
    ///   triggering background refreshes.
    public init(refreshAction: RefreshAction? = nil) {
        self.refreshAction = refreshAction
    }

    // MARK: - currentToken()

    /// Returns the current access token if valid, `nil` if expired or not set.
    /// Never writes to disk or logs the returned string.
    public func currentToken() -> String? {
        guard let t = token, let exp = expiresAt, exp > Date() else {
            return nil
        }
        return t
    }

    // MARK: - setToken(_:expiresAt:)

    /// Store a newly acquired token. Cancels any in-flight refresh task
    /// and schedules the next one.
    public func setToken(_ token: String, expiresAt: Date) {
        self.token = token
        self.expiresAt = expiresAt
        self.consecutiveFailures = 0
        self.state = .unlocked(expiresAt: expiresAt)

        // Cancel any previous refresh task.
        refreshTask?.cancel()
        refreshTask = nil

        // Schedule auto-refresh unless the expiry is in the past already.
        guard expiresAt > Date() else { return }
        scheduleRefresh(expiresAt: expiresAt)
    }

    // MARK: - invalidate()

    /// Wipe the in-memory token immediately and cancel any pending refresh.
    public func invalidate() {
        token = nil
        expiresAt = nil
        consecutiveFailures = 0
        refreshTask?.cancel()
        refreshTask = nil
        state = .locked
    }

    // MARK: - Private: refresh scheduling

    private func scheduleRefresh(expiresAt: Date) {
        guard let action = refreshAction else { return }

        let delay = max(0, expiresAt.timeIntervalSinceNow - Self.refreshLeadSeconds)
        refreshTask = Task {
            // Sleep until T-60s before expiry.
            if delay > 0 {
                try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            }
            guard !Task.isCancelled else { return }
            await self.attemptRefresh(action: action)
        }
    }

    private func attemptRefresh(action: RefreshAction) async {
        var backoff = Self.initialBackoffSeconds

        while !Task.isCancelled {
            do {
                let result = try await action()
                // Success — update token and reset failure count.
                // setToken is synchronous; no `await` needed (already in actor context).
                setToken(result.token, expiresAt: result.expiresAt)
                return
            } catch {
                consecutiveFailures += 1
                if consecutiveFailures >= Self.maxConsecutiveFailures {
                    token = nil
                    expiresAt = nil
                    state = .error(.maxRefreshFailuresReached(count: consecutiveFailures))
                    return
                }
                // Backoff before retry.
                let sleepNS = UInt64(min(backoff, Self.maxBackoffSeconds) * 1_000_000_000)
                try? await Task.sleep(nanoseconds: sleepNS)
                backoff = min(backoff * 2, Self.maxBackoffSeconds)
            }
        }
    }
}
