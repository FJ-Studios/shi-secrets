import Foundation

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// PeerCred — kernel-enforced caller-uid extraction (BR-D-01).
//
// Linux:  getsockopt(SO_PEERCRED) → `ucred { pid, uid, gid }`
// Darwin: getsockopt(SOL_LOCAL, LOCAL_PEERCRED) → `xucred`
//
// Callers MUST NOT accept any uid supplied in the request payload — the
// uid returned here is the only trusted identity.
//
// Tests verify the kernel-side extraction on the current platform; the
// parameterised test case `current platform` runs whichever branch the
// build supports.

public struct PeerCredentials: Sendable, Equatable {
    public let uid: UInt32
    public let pid: Int32?

    public init(uid: UInt32, pid: Int32?) {
        self.uid = uid
        self.pid = pid
    }
}

public enum PeerCredError: Swift.Error, Sendable, Equatable {
    case unsupportedPlatform
    case getsockoptFailed(errno: Int32)
}

/// Reads peer credentials from a connected unix-domain socket FD.
public func peerCredentials(fd: Int32) throws -> PeerCredentials {
    #if os(Linux)
    var cred = ucred()
    var len = socklen_t(MemoryLayout<ucred>.size)
    let result = withUnsafeMutablePointer(to: &cred) { ptr -> Int32 in
        getsockopt(fd, SOL_SOCKET, SO_PEERCRED, ptr, &len)
    }
    guard result == 0 else {
        throw PeerCredError.getsockoptFailed(errno: errno)
    }
    return PeerCredentials(uid: UInt32(cred.uid), pid: Int32(cred.pid))
    #elseif canImport(Darwin)
    var cred = xucred()
    var len = socklen_t(MemoryLayout<xucred>.size)
    let result = withUnsafeMutablePointer(to: &cred) { ptr -> Int32 in
        getsockopt(fd, SOL_LOCAL, LOCAL_PEERCRED, ptr, &len)
    }
    guard result == 0 else {
        throw PeerCredError.getsockoptFailed(errno: errno)
    }
    return PeerCredentials(uid: UInt32(cred.cr_uid), pid: nil)
    #else
    throw PeerCredError.unsupportedPlatform
    #endif
}

/// Explicit "the caller-supplied uid is IGNORED" helper. Broker request
/// handlers call this over any payload-level uid field so the read is
/// visible + greppable in audit logs.
public func trustedUid(kernelReportedUid: UInt32, payloadSuppliedUid: UInt32?) -> UInt32 {
    _ = payloadSuppliedUid   // intentionally discarded — kernel uid is truth
    return kernelReportedUid
}

/// Current-platform sentinel used by tests + diagnostics.
public enum PeerCredPlatform: String, Sendable, Equatable {
    case linux
    case darwin
    case unsupported

    public static var current: PeerCredPlatform {
        #if os(Linux)
        return .linux
        #elseif canImport(Darwin)
        return .darwin
        #else
        return .unsupported
        #endif
    }
}
