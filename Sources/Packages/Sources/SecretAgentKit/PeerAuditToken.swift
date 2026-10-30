import Foundation
import Security

/// The audit token of the process on the other end of a unix socket. Unlike a pid, it also contains the pid version,
/// so it names exactly one process even if the pid is reused later.
public struct PeerAuditToken: @unchecked Sendable {

    var raw: audit_token_t

    public var pid: Int32 {
        Int32(bitPattern: raw.val.5)
    }

    /// Whether exactly this process (pid and pid version) still exists. Security.framework refuses audit tokens whose
    /// pid version does not match the running process.
    public var isLive: Bool {
        var token = raw
        let data = unsafe Data(bytes: &token, count: MemoryLayout<audit_token_t>.size)
        let attributes = [kSecGuestAttributeAudit: data] as CFDictionary
        var code: SecCode?
        return unsafe SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess
    }

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
