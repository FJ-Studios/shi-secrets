import Foundation

/// Thread-safe mutable clock for tests that need to advance time across
/// async boundaries without tripping Sendable-capture diagnostics.
final class MutableClock: @unchecked Sendable {
    private let lock = NSLock()
    private var current: Date

    init(time: Date) {
        self.current = time
    }

    func get() -> Date {
        lock.lock(); defer { lock.unlock() }
        return current
    }

    func set(_ t: Date) {
        lock.lock(); defer { lock.unlock() }
        current = t
    }
}
