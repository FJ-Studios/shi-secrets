import Foundation

// Container+Secrets — extension hook the ShikkiSecretsKit module uses to
// declare its feature-module type on the container (Task 41).
//
// Keeping the extension point in ShikkiCore (the owning-package of
// DIContainer) prevents a circular dependency and makes the convention
// discoverable: any feature that ships a `DIModule` adds a mirror
// extension here. Wave 4's `Bootstrap` calls through this extension
// after systemd-creds unseal completes.

extension DIContainer {
    /// Install a single module's registrations. Convenience shim so
    /// call-sites read `container.install(ShikkiSecretsModule())`
    /// instead of `ShikkiSecretsModule().register(into: container)`.
    public func install(_ module: DIModule) {
        module.register(into: self)
    }
}
