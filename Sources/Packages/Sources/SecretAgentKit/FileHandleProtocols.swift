import Foundation

extension FileHandle {

    /// The pid of the process on the other end of a unix socket, or `nil` if it is unknown.
    public var pidOfConnectedProcess: Int32? {
        var pid: Int32 = 0
        var len = socklen_t(MemoryLayout<Int32>.size)
        let result = unsafe getsockopt(fileDescriptor, SOL_LOCAL, LOCAL_PEERPID, &pid, &len)
        guard result == 0, len == socklen_t(MemoryLayout<Int32>.size), pid > 0 else { return nil }
        return pid
    }

}
