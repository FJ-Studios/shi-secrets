import Foundation

// DIContainer — minimal service locator used by the ShikkiSecrets broker
// (Wave 3 scaffold for Task 41 ShikkiSecretsModule registration).
//
// ShikkiCore does not yet carry a full DI implementation (CoreKit owns
// the production one in the wider monorepo). The secrets-broker feature
// needs *a* container surface now so ShikkiSecretsModule can register +
// resolve before Bootstrap (Wave 4) hands in the unsealed signing key.
//
// Scope is deliberately narrow:
//   - `registerSingleton<T>` — stores an eager instance
//   - `registerLazy<T>` — stores a factory invoked on first resolve
//   - `resolve<T>` — returns the instance, throws if missing or guarded
//   - `markSealed(_:)` — guard resolution until a prerequisite completes
//
// A `DIModule` protocol lets features bundle their registrations into a
// single `register(into:)` call. See `ShikkiSecretsModule` for the
// feature-local one.

public protocol DIModule {
    func register(into container: DIContainer)
}

public final class DIContainer: @unchecked Sendable {

    public enum ResolveError: Swift.Error, Sendable, Equatable, CustomStringConvertible {
        case notRegistered(type: String)
        case sealed(type: String)

        public var description: String {
            switch self {
            case .notRegistered(let t): return "DIContainer: type '\(t)' not registered"
            case .sealed(let t):        return "DIContainer: type '\(t)' is sealed (unseal prerequisite)"
            }
        }
    }

    private let lock = NSRecursiveLock()
    private var singletons: [ObjectIdentifier: Any] = [:]
    private var factories: [ObjectIdentifier: () -> Any] = [:]
    private var sealed: Set<ObjectIdentifier> = []

    public init() {}

    // MARK: - Registration

    public func registerSingleton<T>(_ type: T.Type, _ instance: T) {
        lock.lock(); defer { lock.unlock() }
        singletons[ObjectIdentifier(type)] = instance
    }

    public func registerLazy<T>(_ type: T.Type, _ factory: @escaping () -> T) {
        lock.lock(); defer { lock.unlock() }
        factories[ObjectIdentifier(type)] = { factory() as Any }
    }

    /// Mark a type as sealed. `resolve(type)` will throw `.sealed` until
    /// `unseal(type)` is invoked (typically by Bootstrap after systemd-creds
    /// unseal completes).
    public func markSealed<T>(_ type: T.Type) {
        lock.lock(); defer { lock.unlock() }
        sealed.insert(ObjectIdentifier(type))
    }

    public func unseal<T>(_ type: T.Type) {
        lock.lock(); defer { lock.unlock() }
        sealed.remove(ObjectIdentifier(type))
    }

    // MARK: - Resolution

    public func resolve<T>(_ type: T.Type = T.self) throws -> T {
        lock.lock(); defer { lock.unlock() }
        let key = ObjectIdentifier(type)
        if sealed.contains(key) {
            throw ResolveError.sealed(type: String(describing: type))
        }
        if let hit = singletons[key] as? T {
            return hit
        }
        if let factory = factories[key] {
            let made = factory()
            guard let cast = made as? T else {
                throw ResolveError.notRegistered(type: String(describing: type))
            }
            singletons[key] = cast    // memoize
            return cast
        }
        throw ResolveError.notRegistered(type: String(describing: type))
    }

    /// Non-throwing resolve. Returns nil if missing or sealed.
    public func tryResolve<T>(_ type: T.Type = T.self) -> T? {
        try? resolve(type)
    }
}
