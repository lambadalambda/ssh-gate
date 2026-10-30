import Foundation
import Testing
@testable import SSHProtocolKit

typealias GrantRequestContext = SSHAgent.ProtocolExtension.GrantRequestContext

func extensionMessage(_ context: GrantRequestContext) -> Data {
    var body = Data([27])
    body.append(Data(GrantRequestContext.name.utf8).lengthAndData)
    body.append(context.encoded)
    return body.lengthAndData
}

func parseGrantRequest(_ message: Data) throws -> GrantRequestContext {
    guard case .protocolExtension(.grantRequest(let context)) = try SSHAgentInputParser().parse(data: message) else {
        throw TestFailure.unexpectedRequest
    }
    return context
}

@Suite struct GrantRequestExtensionTests {

    @Test func roundTrip() throws {
        let login = GrantRequestContext(keyBlob: Data([1, 2]), purpose: .login(host: "git.example", port: 2222, user: "git"), seconds: 3600, reason: "push branch")
        #expect(try parseGrantRequest(extensionMessage(login)) == login)
        let sign = GrantRequestContext(keyBlob: Data(), purpose: .signature(namespace: "git"), seconds: 600, reason: "")
        #expect(try parseGrantRequest(extensionMessage(sign)) == sign)
    }

    @Test(arguments: [
        GrantRequestContext(keyBlob: Data(), purpose: .login(host: "", port: 22, user: "git"), seconds: 60, reason: ""),
        GrantRequestContext(keyBlob: Data(), purpose: .login(host: "a.example", port: 22, user: ""), seconds: 60, reason: ""),
        GrantRequestContext(keyBlob: Data(), purpose: .login(host: "a.example", port: 0, user: "git"), seconds: 60, reason: ""),
        GrantRequestContext(keyBlob: Data(), purpose: .login(host: "a.example\nb", port: 22, user: "git"), seconds: 60, reason: ""),
        GrantRequestContext(keyBlob: Data(), purpose: .login(host: "gіthub.com", port: 22, user: "git"), seconds: 60, reason: ""),
        GrantRequestContext(keyBlob: Data(), purpose: .login(host: String(repeating: "a", count: 254), port: 22, user: "git"), seconds: 60, reason: ""),
        GrantRequestContext(keyBlob: Data(), purpose: .signature(namespace: ""), seconds: 60, reason: ""),
        GrantRequestContext(keyBlob: Data(), purpose: .signature(namespace: "git"), seconds: 0, reason: ""),
        GrantRequestContext(keyBlob: Data(), purpose: .signature(namespace: "git"), seconds: 60, reason: "line\u{1B}[31m"),
        GrantRequestContext(keyBlob: Data(), purpose: .signature(namespace: "git"), seconds: 60, reason: String(repeating: "x", count: 501)),
    ])
    func invalidRequests(context: GrantRequestContext) {
        #expect(throws: (any Error).self) { try parseGrantRequest(extensionMessage(context)) }
    }

    @Test func unknownKindAndTrailingData() {
        let valid = GrantRequestContext(keyBlob: Data(), purpose: .signature(namespace: "git"), seconds: 60, reason: "")
        var trailing = Data([27])
        trailing.append(Data(GrantRequestContext.name.utf8).lengthAndData)
        trailing.append(valid.encoded + Data([0]))
        #expect(throws: (any Error).self) { try parseGrantRequest(trailing.lengthAndData) }
        let unknownKind = valid.encoded.replacing(Data("sign".utf8), with: Data("exec".utf8))
        var message = Data([27])
        message.append(Data(GrantRequestContext.name.utf8).lengthAndData)
        message.append(unknownKind)
        #expect(throws: (any Error).self) { try parseGrantRequest(message.lengthAndData) }
    }

}
