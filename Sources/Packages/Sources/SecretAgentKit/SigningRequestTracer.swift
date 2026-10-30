import Foundation
import AppKit
import Security
import SecretKit

/// An object responsible for generating ``SecretKit.SigningRequestProvenance`` objects.
struct SigningRequestTracer {
}

extension SigningRequestTracer {

    /// Generates a ``SecretKit.SigningRequestProvenance`` from a ``FileHandle``.
    ///
    /// The connecting process is identified by its audit token. The chain stops at the first GUI app, at a process
    /// without a parent, or where a pid was reused: a parent that started after its child is not the real parent. If the
    /// connecting process itself cannot be identified, the chain contains only an unknown process, which no grant can
    /// match.
    /// - Parameter fileHandle: The reader involved in processing the request.
    /// - Returns: A ``SecretKit.SigningRequestProvenance`` describing the origin of the request.
    func provenance(from fileHandle: FileHandle) -> SigningRequestProvenance {
        let acceptedAt = Date()
        guard let token = fileHandle.auditTokenOfConnectedProcess else {
            return SigningRequestProvenance(root: Self.unknownProcess(pid: -1))
        }
        let pid = token.pid
        // The token still names a live process after the lookup, so the pid was not reused in between.
        guard let root = process(from: pid), let started = root.startTime, started <= acceptedAt, token.isLive else {
            return SigningRequestProvenance(root: Self.unknownProcess(pid: pid))
        }
        var provenance = SigningRequestProvenance(root: root)
        while NSRunningApplication(processIdentifier: provenance.origin.pid) == nil,
              let parentPID = provenance.origin.parentPID,
              let parent = process(from: parentPID),
              Self.isPlausibleParent(parent, of: provenance.origin) {
            provenance.chain.append(parent)
        }
        return provenance
    }

    /// A parent must have started no later than its child, else its pid was reused.
    static func isPlausibleParent(_ parent: SigningRequestProvenance.Process, of child: SigningRequestProvenance.Process) -> Bool {
        guard let parentStart = parent.startTime, let childStart = child.startTime else { return false }
        return parentStart <= childStart
    }

    static func unknownProcess(pid: Int32) -> SigningRequestProvenance.Process {
        .init(pid: pid, processName: "unknown", appName: nil, iconURL: nil, path: "", validSignature: false, parentPID: nil)
    }

    /// Generates a `kinfo_proc` representation of the provided process ID.
    /// - Parameter pid: The process ID to look up.
    /// - Returns: a `kinfo_proc` struct describing the process ID, or `nil` if there is no such process.
    func pidAndNameInfo(from pid: Int32) -> kinfo_proc? {
        var info = unsafe kinfo_proc()
        let size = unsafe MemoryLayout<kinfo_proc>.size
        var len = size
        var name: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        let result = unsafe sysctl(&name, UInt32(name.count), &info, &len, nil, 0)
        guard result == 0, len == size else { return nil }
        return unsafe info
    }

    /// Generates a ``SecretKit.SigningRequestProvenance.Process`` from a provided process ID.
    /// - Parameter pid: The process ID to look up.
    /// - Returns: A ``SecretKit.SigningRequestProvenance.Process`` describing the process, or `nil` if there is no such process.
    func process(from pid: Int32) -> SigningRequestProvenance.Process? {
        guard var pidAndNameInfo = unsafe self.pidAndNameInfo(from: pid) else { return nil }
        let ppid = unsafe pidAndNameInfo.kp_eproc.e_ppid != 0 ? pidAndNameInfo.kp_eproc.e_ppid : nil
        let start = unsafe pidAndNameInfo.kp_proc.p_un.__p_starttime
        let startTime = start.tv_sec != 0 ? Date(timeIntervalSince1970: TimeInterval(start.tv_sec) + TimeInterval(start.tv_usec) / 1_000_000) : nil
        let procName = unsafe withUnsafeMutablePointer(to: &pidAndNameInfo.kp_proc.p_comm.0) { pointer in
            unsafe String(cString: pointer)
        }

        var pathBuffer = [UInt8](repeating: 0, count: Int(MAXPATHLEN))
        _ = unsafe proc_pidpath(pid, &pathBuffer, UInt32(MAXPATHLEN))
        let path = String(decoding: pathBuffer.prefix { $0 != 0 }, as: UTF8.self)

        return SigningRequestProvenance.Process(pid: pid, processName: procName, appName: appName(for: pid), iconURL: iconURL(for: pid), path: path, validSignature: hasValidSignature(pid: pid), parentPID: ppid, startTime: startTime, isApp: NSRunningApplication(processIdentifier: pid) != nil)
    }

    /// Checks the code signature of a process. A process that exits during the check has no valid signature.
    func hasValidSignature(pid: Int32) -> Bool {
        var secCode: Unmanaged<SecCode>?
        guard unsafe SecCodeCreateWithPID(pid, SecCSFlags(), &secCode) == errSecSuccess, let code = unsafe secCode?.takeRetainedValue() else {
            return false
        }
        let flags: SecCSFlags = [.considerExpiration, .enforceRevocationChecks]
        return SecCodeCheckValidity(code, flags, nil) == errSecSuccess
    }

    /// Looks up the URL for the icon of a process ID, if it has one.
    /// - Parameter pid: The process ID to look up.
    /// - Returns: A URL to the icon, if the process has one.
    func iconURL(for pid: Int32) -> URL? {
        do {
            if let app = NSRunningApplication(processIdentifier: pid), let icon = app.icon?.tiffRepresentation {
                let temporaryURL = URL(fileURLWithPath: (NSTemporaryDirectory() as NSString).appendingPathComponent("\(app.bundleIdentifier ?? UUID().uuidString).png"))
                if FileManager.default.fileExists(atPath: temporaryURL.path) {
                    return temporaryURL
                }
                let bitmap = NSBitmapImageRep(data: icon)
                try bitmap?.representation(using: .png, properties: [:])?.write(to: temporaryURL)
                return temporaryURL
            }
        } catch {
        }
        return nil
    }

    /// Looks up the application name of a process ID, if it has one.
    /// - Parameter pid: The process ID to look up.
    /// - Returns: The process's display name, if the process has one.
    func appName(for pid: Int32) -> String? {
        NSRunningApplication(processIdentifier: pid)?.localizedName
    }

}

//// from SecTask.h
@_silgen_name("SecCodeCreateWithPID")
@discardableResult func SecCodeCreateWithPID(_: Int32, _: SecCSFlags, _: UnsafeMutablePointer<Unmanaged<SecCode>?>!) -> OSStatus
