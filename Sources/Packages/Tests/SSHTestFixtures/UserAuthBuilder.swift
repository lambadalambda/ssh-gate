import Foundation
import SSHProtocolKit

/// Frames a sign request for `data` like ssh does.
public func signRequest(key: Data, data: Data) -> Data {
    var body = Data([13])
    body.append(key.lengthAndData)
    body.append(data.lengthAndData)
    body.append(Data([0, 0, 0, 0]))
    return body.lengthAndData
}

/// The fields of a userauth request; tests change single fields.
public struct UserAuth: Sendable {
    public var sessionID = Data(repeating: 7, count: 32)
    public var message: UInt8 = 50
    public var user = "root"
    public var service = "ssh-connection"
    public var method = "publickey-hostbound-v00@openssh.com"
    public var sigFollows: UInt8 = 1
    public var algorithm = "ssh-ed25519"
    public var key = CapturedFixtures.userKey
    public var hostKey: Data? = CapturedFixtures.logins["ed25519"]!.hostKey
    public var trailing = Data()

    public init() {}

    public var data: Data {
        var d = sessionID.lengthAndData
        d.append(message)
        d.append(Data(user.utf8).lengthAndData)
        d.append(Data(service.utf8).lengthAndData)
        d.append(Data(method.utf8).lengthAndData)
        d.append(sigFollows)
        d.append(Data(algorithm.utf8).lengthAndData)
        d.append(key.lengthAndData)
        if let hostKey { d.append(hostKey.lengthAndData) }
        d.append(trailing)
        return d
    }

    public var request: Data { signRequest(key: key, data: data) }
}

