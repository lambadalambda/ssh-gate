import Foundation
import Testing
import SecretKit
@testable import SecretAgentKit

@Suite struct ProvenanceConsistencyTests {

    @Test func parentMustNotBeYoungerThanChild() {
        let c = chain("ssh", "zsh")
        #expect(SigningRequestTracer.isPlausibleParent(c[1], of: c[0]))
        #expect(!SigningRequestTracer.isPlausibleParent(c[1].with(startTime: Date(timeIntervalSince1970: 5000)), of: c[0]))
    }

    @Test func unknownStartTimeIsNotPlausible() {
        let c = chain("ssh", "zsh")
        let unknown = SigningRequestProvenance.Process(pid: 5, processName: "?", appName: nil, iconURL: nil, path: "", validSignature: false, parentPID: nil)
        #expect(!SigningRequestTracer.isPlausibleParent(unknown, of: c[0]))
        #expect(!SigningRequestTracer.isPlausibleParent(c[1], of: unknown))
    }

    @Test func lookupOfMissingProcessFails() {
        // pid_max on macOS is 99999.
        #expect(SigningRequestTracer().process(from: 99_999_999) == nil)
    }

}

@Suite struct PeerPIDTests {

    @Test func connectedPeerIsSelf() throws {
        let path = "/tmp/secretive-peer-\(getpid()).sock"
        unlink(path)
        defer { unlink(path) }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        unsafe withUnsafeMutableBytes(of: &addr.sun_path) { buffer in
            unsafe path.utf8CString.withUnsafeBytes { unsafe buffer.copyMemory(from: $0) }
        }
        let size = socklen_t(MemoryLayout<sockaddr_un>.size)
        let server = socket(AF_UNIX, SOCK_STREAM, 0)
        let client = socket(AF_UNIX, SOCK_STREAM, 0)
        defer { close(server); close(client) }
        try #require(unsafe withUnsafePointer(to: &addr) { unsafe bind(server, UnsafeRawPointer($0).assumingMemoryBound(to: sockaddr.self), size) } == 0)
        try #require(listen(server, 1) == 0)
        try #require(unsafe withUnsafePointer(to: &addr) { unsafe connect(client, UnsafeRawPointer($0).assumingMemoryBound(to: sockaddr.self), size) } == 0)
        let accepted = accept(server, nil, nil)
        try #require(accepted >= 0)
        let handle = FileHandle(fileDescriptor: accepted, closeOnDealloc: true)
        #expect(handle.pidOfConnectedProcess == getpid())
    }

    @Test func nonSocketHasNoPeer() {
        #expect(FileHandle.nullDevice.pidOfConnectedProcess == nil)
    }

}
