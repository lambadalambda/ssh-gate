import Foundation
import Testing
@testable import SSHProtocolKit
import SSHTestFixtures

typealias ConnectionPayload = SSHAgent.Request.SignatureRequestContext.SignaturePayload.DecodedPayload.SSHConnectionPayload
typealias SessionBind = SSHAgent.ProtocolExtension.OpenSSHExtension.SessionBindContext

func parseBind(_ data: Data) throws -> SessionBind {
    guard case .protocolExtension(.openSSH(.sessionBind(let bind))) = try SSHAgentInputParser().parse(data: data) else {
        throw TestFailure.unexpectedRequest
    }
    return bind
}

func parseConnection(_ data: Data) throws -> ConnectionPayload {
    guard case .signRequest(let context) = try SSHAgentInputParser().parse(data: data),
          case .sshConnection(let payload) = context.dataToSign.decoded else {
        throw TestFailure.unexpectedRequest
    }
    return payload
}

enum TestFailure: Error {
    case unexpectedRequest
}

@Suite struct CapturedLoginTests {

    @Test(arguments: CapturedFixtures.logins.keys.sorted())
    func bindVerifiesWithFullHostKey(name: String) throws {
        let login = try #require(CapturedFixtures.logins[name])
        let bind = try parseBind(login.sessionBind)
        #expect(bind.hostKey == login.hostKey)
        #expect(!bind.forwarding)
    }

    @Test(arguments: CapturedFixtures.logins.keys.sorted())
    func userauthMatchesBind(name: String) throws {
        let login = try #require(CapturedFixtures.logins[name])
        let bind = try parseBind(login.sessionBind)
        let payload = try parseConnection(login.signRequest)
        #expect(payload.sessionID == bind.sessionID)
        #expect(payload.hostKey == login.hostKey)
        #expect(payload.username == "root")
        #expect(payload.publicKey == CapturedFixtures.userKey)
    }

    @Test(arguments: CapturedFixtures.logins.keys.sorted())
    func tamperedBindIsRejected(name: String) throws {
        var bind = try #require(CapturedFixtures.logins[name]).sessionBind
        bind[bind.count - 10] ^= 0x01 // inside the signature
        #expect(throws: (any Error).self) { try parseBind(bind) }
    }

    @Test func forwardingFlag() throws {
        var bind = try #require(CapturedFixtures.logins["ed25519"]).sessionBind
        bind[bind.count - 1] = 1
        #expect(try parseBind(bind).forwarding)
        bind[bind.count - 1] = 2
        #expect(throws: (any Error).self) { try parseBind(bind) }
    }

    @Test func hostsDifferByFullKey() throws {
        let p256 = try parseConnection(try #require(CapturedFixtures.logins["ecdsa256"]).signRequest)
        let p384 = try parseConnection(try #require(CapturedFixtures.logins["ecdsa384"]).signRequest)
        #expect(p256.hostKey != p384.hostKey)
    }

    @Test func gitSignature() throws {
        guard case .signRequest(let context) = try SSHAgentInputParser().parse(data: CapturedFixtures.gitSignRequest),
              case .sshSig(let payload) = context.dataToSign.decoded else {
            Issue.record("not an SSHSIG request")
            return
        }
        #expect(payload.namespace == "git")
    }

}

@Suite struct StrictUserAuthTests {

    @Test func validRequests() throws {
        #expect(try parseConnection(UserAuth().request).hostKey != nil)
        var plain = UserAuth()
        plain.method = "publickey"
        plain.hostKey = nil
        #expect(try parseConnection(plain.request).hostKey == nil)
    }

    static let invalid: [(String, @Sendable (inout UserAuth) -> Void)] = [
        ("wrong service", { $0.service = "ssh-userauth" }),
        ("password method", { $0.method = "password" }),
        ("sig-follows 0", { $0.sigFollows = 0 }),
        ("sig-follows 2", { $0.sigFollows = 2 }),
        ("algorithm mismatch", { $0.algorithm = "ecdsa-sha2-nistp256" }),
        ("long session ID", { $0.sessionID = Data(repeating: 1, count: 65) }),
        ("empty session ID", { $0.sessionID = Data() }),
        ("trailing data", { $0.trailing = Data([0]) }),
        ("hostbound without host key", { $0.hostKey = nil }),
        ("publickey with host key", { $0.method = "publickey" }),
    ]

    @Test(arguments: invalid.indices)
    func invalidRequestHasNoDecodedPayload(index: Int) throws {
        var auth = UserAuth()
        Self.invalid[index].1(&auth)
        #expect(throws: (any Error).self, "\(Self.invalid[index].0)") { try parseConnection(auth.request) }
    }

    @Test func rsaAlgorithmsMatchRSAKey() {
        #expect(SSHAgentInputParser.algorithm("rsa-sha2-256", matchesKeyType: "ssh-rsa"))
        #expect(SSHAgentInputParser.algorithm("rsa-sha2-512", matchesKeyType: "ssh-rsa"))
        #expect(SSHAgentInputParser.algorithm("ecdsa-sha2-nistp256", matchesKeyType: "ecdsa-sha2-nistp256"))
        #expect(!SSHAgentInputParser.algorithm("rsa-sha2-256", matchesKeyType: "ssh-ed25519"))
    }

}

@Suite struct HostKeyVerifierEncodingTests {

    @Test func mpintMustBeCanonical() throws {
        #expect(try HostKeySignatureVerifier.unsignedMPInt(Data([0x01, 0x02])) == Data([0x01, 0x02]))
        #expect(try HostKeySignatureVerifier.unsignedMPInt(Data([0x00, 0x80])) == Data([0x80]))
        #expect(try HostKeySignatureVerifier.unsignedMPInt(Data()) == Data())
        // Negative, and not minimal.
        #expect(throws: (any Error).self) { try HostKeySignatureVerifier.unsignedMPInt(Data([0x80])) }
        #expect(throws: (any Error).self) { try HostKeySignatureVerifier.unsignedMPInt(Data([0x00, 0x01])) }
    }

    @Test func bitCount() {
        #expect(HostKeySignatureVerifier.bitCount(Data([0x01])) == 1)
        #expect(HostKeySignatureVerifier.bitCount(Data([0x7f] + Array(repeating: 0, count: 127))) == 1023)
        #expect(HostKeySignatureVerifier.bitCount(Data([0x80] + Array(repeating: 0, count: 127))) == 1024)
    }

}
