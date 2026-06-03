// KernelStubs — minimal re-declarations of ShikkiCore kernel types needed
// by ShiSecretsKit when building as a standalone plugin outside the
// shikki monorepo.
//
// Source of truth for these types remains
// packages/ShikkiCore/Sources/ShikkiCore/Kernel/*.swift in the monorepo.
// These stubs exist ONLY to break the direct monorepo dependency while
// preserving the same protocol/enum shapes.
//
// W3 of features/shi-secrets-uri-scheme-and-plugin-extraction-2026-05-31.md.

import Foundation

/// A job the kernel can dispatch. Minimal protocol shape — extension
/// points (health, cancel) live in the full ShikkiCore version.
public protocol ShikkiKernelJob: Sendable {
    func run() async throws
}

/// Kernel scheduling primitives — interval or named event channel.
public enum Schedule: Sendable, Equatable {
    case interval(TimeInterval)
    case onEvent(String)
}

/// Per-service QoS cgroup classification.
public enum QoSTrack: String, Codable, Sendable, CaseIterable, Equatable {
    case hot
    case warm
    case cool
    case external
}

/// A registered job entry in the kernel table.
public struct JobRegistration: Sendable {
    public let id: String
    public let schedule: Schedule
    public let qos: QoSTrack
    public let job: any ShikkiKernelJob

    public init(id: String, schedule: Schedule, qos: QoSTrack, job: any ShikkiKernelJob) {
        self.id = id
        self.schedule = schedule
        self.qos = qos
        self.job = job
    }
}

/// Minimal kernel registry for job registration.
public actor ShikkiKernel {

    public enum RegistrationError: Swift.Error, Sendable, Equatable {
        case duplicateId(String)
    }

    private var registry: [String: JobRegistration] = [:]

    public init() {}

    public func register(
        id: String,
        job: any ShikkiKernelJob,
        schedule: Schedule,
        qos: QoSTrack
    ) throws {
        if registry[id] != nil {
            throw RegistrationError.duplicateId(id)
        }
        registry[id] = JobRegistration(id: id, schedule: schedule, qos: qos, job: job)
    }

    public func registrations() -> [JobRegistration] {
        Array(registry.values)
    }

    public func registration(id: String) -> JobRegistration? {
        registry[id]
    }
}
