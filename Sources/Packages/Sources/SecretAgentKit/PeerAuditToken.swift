import Foundation

/// The audit token of the process on the other end of a unix socket. Unlike a pid, it also contains the pid version,
/// so it names exactly one process even if the pid is reused later.
public struct PeerAuditToken: @unchecked Sendable {

    var raw: audit_token_t

    public var pid: Int32 {
        Int32(bitPattern: raw.val.5)
    }

    /// Whether exactly this process (pid and pid version) still exists. The kernel refuses audit tokens whose pid
    /// version does not match the running process with ESRCH. Unlike Security.framework, this does not read the
    /// process's binary, which the app sandbox does not allow for most paths.
    public var isLive: Bool {
        var token = raw
        var status: UInt32 = 0
        return unsafe csops_audittoken(pid, Self.csOpsStatus, &status, MemoryLayout<UInt32>.size, &token) == 0
    }

    /// CS_OPS_STATUS from sys/codesign.h.
    static let csOpsStatus: UInt32 = 0

}

extension FileHandle {

    /// The audit token of the process on the other end of a unix socket, or `nil` if it is unknown.
    public var auditTokenOfConnectedProcess: PeerAuditToken? {
        var token = audit_token_t()
        var len = socklen_t(MemoryLayout<audit_token_t>.size)
        let result = unsafe getsockopt(fileDescriptor, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &len)
        guard result == 0, len == socklen_t(MemoryLayout<audit_token_t>.size) else { return nil }
        let peer = PeerAuditToken(raw: token)
        return peer.pid > 0 ? peer : nil
    }

}

// From sys/codesign.h; part of libsystem_kernel, but not in the public SDK headers.
@_silgen_name("csops_audittoken")
func csops_audittoken(_ pid: pid_t, _ ops: UInt32, _ useraddr: UnsafeMutableRawPointer?, _ usersize: Int, _ token: UnsafeMutablePointer<audit_token_t>) -> Int32
