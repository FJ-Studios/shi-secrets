import Testing
import Foundation
@testable import ShiSecretsKit

/// Sendable clock holder for tests — allows mutation via actor.
private final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var current: Date
    init(_ initial: Date) { self.current = initial }
    func now() -> Date {
        lock.lock(); defer { lock.unlock() }
        return current
    }
    func advance(to date: Date) {
        lock.lock(); defer { lock.unlock() }
        current = date
    }
}

@Suite("InMemoryCache — TP-SSEC-06")
struct InMemoryCacheTests {

    // Helper: build a URI without going through the parser.
    private func uri(_ ns: String, _ key: String) -> ShiSecretURI {
        // The parser is the only constructor — use it.
        // swiftlint:disable:next force_try
        try! ShiSecretURI.parse("shi-secret://\(ns)/\(key)")
    }

    @Test("stores + retrieves before TTL expiry")
    func storesAndRetrievesBeforeTTL() async {
        let now = Date(timeIntervalSinceReferenceDate: 1000)
        let cache = InMemoryCache(ttl: 30, clock: { now })
        let key = uri("obyw", "pb-admin")
        await cache.set(key, .init(plaintext: "hello"))

        let got = await cache.get(key)
        #expect(got?.plaintext == "hello")
    }

    @Test("returns nil + evicts after TTL expiry")
    func evictsAfterTTL() async {
        let clock = TestClock(Date(timeIntervalSinceReferenceDate: 1000))
        let cache = InMemoryCache(ttl: 30, clock: { clock.now() })
        let key = uri("obyw", "pb-admin")
        await cache.set(key, .init(plaintext: "hello"))

        // Advance past TTL.
        clock.advance(to: Date(timeIntervalSinceReferenceDate: 1031))
        let got = await cache.get(key)
        #expect(got == nil)

        // After expired get(), the entry should be evicted from store.
        let count = await cache.count()
        #expect(count == 0)
    }

    @Test("invalidate removes entry")
    func invalidateRemovesEntry() async {
        let now = Date(timeIntervalSinceReferenceDate: 1000)
        let cache = InMemoryCache(ttl: 30, clock: { now })
        let key = uri("obyw", "pb-admin")
        await cache.set(key, .init(plaintext: "hello"))

        await cache.invalidate(key)
        let got = await cache.get(key)
        #expect(got == nil)
    }

    @Test("evictExpired clears expired in bulk")
    func evictExpiredBulk() async {
        let clock = TestClock(Date(timeIntervalSinceReferenceDate: 1000))
        let cache = InMemoryCache(ttl: 30, clock: { clock.now() })
        await cache.set(uri("obyw", "a"), .init(plaintext: "a"))
        await cache.set(uri("obyw", "b"), .init(plaintext: "b"))
        let preCount = await cache.count()
        #expect(preCount == 2)

        clock.advance(to: Date(timeIntervalSinceReferenceDate: 1100))
        await cache.evictExpired()
        let postCount = await cache.count()
        #expect(postCount == 0)
    }

    @Test("BR-SSEC-03: in-memory only — no disk artifacts created")
    func noDiskResidency() async {
        let tmpDir = FileManager.default.temporaryDirectory
        let cwd = FileManager.default.currentDirectoryPath

        let before = (try? FileManager.default.contentsOfDirectory(atPath: tmpDir.path)) ?? []
        let beforeCwd = (try? FileManager.default.contentsOfDirectory(atPath: cwd)) ?? []

        let cache = InMemoryCache(ttl: 30)
        for i in 0..<10 {
            await cache.set(uri("obyw", "k\(i)"), .init(plaintext: "v\(i)"))
        }

        let after = (try? FileManager.default.contentsOfDirectory(atPath: tmpDir.path)) ?? []
        let afterCwd = (try? FileManager.default.contentsOfDirectory(atPath: cwd)) ?? []
        #expect(after.count == before.count, "cache must not create files in tmp")
        #expect(afterCwd.count == beforeCwd.count, "cache must not create files in cwd")
    }
}
