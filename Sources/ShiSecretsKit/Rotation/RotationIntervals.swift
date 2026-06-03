import Foundation

// RotationIntervals — named constants for the four kernel-job tick
// intervals (BR-C-0X) and the `RotationEngine.retryBackoffSeconds` retry
// cadence.
//
// Review finding #13: hoisting the magic numbers 300 / 1_800 / 7_200 /
// 21_600 off the `BrokerDaemon.registerKernelJobs()` call site into one
// named namespace keeps the "kernel tick cadence" review surface in a
// single grep target. Colocated with `RotationEngine.retryBackoffSeconds`
// so ops can scan one file when adjusting cadence.

public enum RotationIntervals {
    /// Hot-tier kernel tick — 5 minutes (BR-C-0X).
    public static let hotSeconds: TimeInterval = 300
    /// Warm-tier kernel tick — 30 minutes (BR-C-0X).
    public static let warmSeconds: TimeInterval = 1_800
    /// Cool-tier kernel tick — 2 hours (BR-C-0X).
    public static let coolSeconds: TimeInterval = 7_200
    /// External-vendor kernel tick — 6 hours (BR-C-0X).
    public static let externalSeconds: TimeInterval = 21_600
}
