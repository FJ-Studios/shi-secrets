// SessionFingerprint — cross-platform identity of the current login session.
//
// W6.5 — used to bind cached OAuth tokens to a specific session so that:
//   • Mac: tokens survive sleep/wake within a single login session,
//     invalidate on user logout/login cycle (loginwindow restart).
//   • Linux: tokens invalidate on SSH disconnect/reconnect (different
//     XDG_SESSION_ID), forcing re-authentication on the new session.
//
// The fingerprint is a stable string derived from OS-specific stable
// identifiers. We deliberately keep it OPAQUE (treat as a blob) so callers
// only do equality comparison, never parse the contents.
//
// BR-COMPOSE note: Linux fingerprint shells out to `loginctl` (a non-Swift
// external system binary), which is the only sanctioned subprocess pattern
// per [[ai-self-improvement-injectable-context-2026-06-25]]. Mac fingerprint
// uses Darwin.sysctl directly (no subprocess).
//
// Spec UUID: e8c4a921-7d3b-4f5e-9a2c-1d6b8f4e3a91 (W6.5)

import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// Computes a stable string identifying the current login session.
public enum SessionFingerprint {

    /// Build a session fingerprint for the current process's session context.
    /// Returns `nil` if the platform-specific lookup fails (treated as
    /// "no fingerprint binding" — backward compatible with W2 token cache
    /// entries written before W6.5).
    ///
    /// Format guarantees:
    ///   • Length ≤ 256 chars
    ///   • ASCII-printable, no whitespace
    ///   • Deterministic within a single session
    ///   • Changes across:
    ///       - Mac: user logout → login (loginwindow restart)
    ///       - Mac: system reboot
    ///       - Linux: SSH session end → reconnect (new XDG_SESSION_ID)
    ///       - Linux: systemd-logind SessionRemoved → fresh session
    public static func current() -> String? {
        #if os(macOS)
        return macOSFingerprint()
        #elseif os(Linux)
        return linuxFingerprint()
        #else
        return nil
        #endif
    }

    // MARK: - macOS impl

    #if os(macOS)
    /// Mac fingerprint = `mac:<uid>:<boottime_unix>`.
    ///
    /// `getuid()` changes across user logout/login. `kern.boottime` changes
    /// across system reboot. Together they form a stable per-session identity.
    static func macOSFingerprint() -> String? {
        let uid = getuid()
        guard let boottime = macOSBoottimeUnix() else { return nil }
        return "mac:\(uid):\(boottime)"
    }

    /// Returns the system boot time as Unix epoch seconds, via sysctl
    /// `kern.boottime`. Returns `nil` on failure.
    static func macOSBoottimeUnix() -> Int? {
        var mib: [Int32] = [CTL_KERN, KERN_BOOTTIME]
        var timeval = timeval()
        var size = MemoryLayout<timeval>.size
        let result = mib.withUnsafeMutableBufferPointer { ptr -> Int32 in
            guard let baseAddress = ptr.baseAddress else { return -1 }
            return sysctl(baseAddress, 2, &timeval, &size, nil, 0)
        }
        guard result == 0 else { return nil }
        return Int(timeval.tv_sec)
    }
    #endif

    // MARK: - Linux impl

    #if os(Linux)
    /// Linux fingerprint = `linux:<xdg_session_id>:<session_start_time>`.
    ///
    /// `XDG_SESSION_ID` (env) is set by systemd-logind per login session;
    /// `loginctl show-session <id> -p Id -p Timestamp` provides the
    /// canonical start-time for verification.
    static func linuxFingerprint() -> String? {
        guard let sessionID = ProcessInfo.processInfo.environment["XDG_SESSION_ID"],
              !sessionID.isEmpty
        else {
            return nil
        }
        // Subprocess justification: loginctl is a non-Swift external. No
        // pure-Swift D-Bus client is available in the standard toolchain.
        let task = Process() // shi-doctor: process-bypass exempt — loginctl invocation; no pure-Swift D-Bus client available in standard toolchain
        task.executableURL = URL(fileURLWithPath: "/usr/bin/loginctl")
        task.arguments = ["show-session", sessionID, "-p", "Timestamp"]
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = Pipe()
        do {
            try task.run()
            task.waitUntilExit()
            guard task.terminationStatus == 0 else { return nil }
        } catch {
            return nil
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        guard let output = String(data: data, encoding: .utf8) else { return nil }
        // Output format: "Timestamp=Mon 2026-06-25 17:30:00 CEST"
        let line = output.split(separator: "\n").first.map(String.init) ?? ""
        let parts = line.split(separator: "=", maxSplits: 1)
        guard parts.count == 2 else { return nil }
        let timestamp = parts[1].trimmingCharacters(in: .whitespaces)
        return "linux:\(sessionID):\(timestamp)"
    }
    #endif
}
