import Foundation

extension SSHAgent.ProtocolExtension {

    /// A request for a grant before the key is used (`request-grant@heldscal.la`).
    ///
    /// Wire format of the extension contents: string key blob (empty: the agent chooses), string kind ("login" or
    /// "sign"), string host, uint32 port, string user, string namespace, uint32 seconds, string reason. Fields that do
    /// not belong to the kind are empty or zero.
    public struct GrantRequestContext: Codable, Sendable, Equatable {

        public enum Purpose: Codable, Sendable, Equatable {
            case login(host: String, port: UInt32, user: String)
            case signature(namespace: String)
        }

        public static let name = "request-grant@heldscal.la"
        static let maxReasonLength = 500

        public let keyBlob: Data
        public let purpose: Purpose
        public let seconds: UInt32
        /// The client's own words. The window shows it as a claim.
        public let reason: String

        public init(keyBlob: Data, purpose: Purpose, seconds: UInt32, reason: String) {
            self.keyBlob = keyBlob
            self.purpose = purpose
            self.seconds = seconds
            self.reason = reason
        }

        init(reading reader: OpenSSHReader) throws {
            keyBlob = try reader.readNextChunk()
            let kind = try reader.readNextChunkAsString()
            let host = try reader.readNextChunkAsString()
            let port = try reader.readNextBytes(as: UInt32.self)
            let user = try reader.readNextChunkAsString()
            let namespace = try reader.readNextChunkAsString()
            seconds = try reader.readNextBytes(as: UInt32.self)
            reason = try reader.readNextChunkAsString()
            guard reader.done, seconds > 0, reason.count <= Self.maxReasonLength, Self.isPrintable(reason) else {
                throw OpenSSHReaderError.incorrectFormat
            }
            switch kind {
            case "login":
                // Host names are ASCII (IDNs in punycode), so look-alike letters cannot imitate another host.
                guard !host.isEmpty, host.count <= 253, host.unicodeScalars.allSatisfy({ $0.isASCII }),
                      !user.isEmpty, (1...65535).contains(port), Self.isPrintable(host), Self.isPrintable(user),
                      !host.contains(" "), !user.contains(" ") else {
                    throw OpenSSHReaderError.incorrectFormat
                }
                purpose = .login(host: host, port: port, user: user)
            case "sign":
                guard !namespace.isEmpty, Self.isPrintable(namespace) else { throw OpenSSHReaderError.incorrectFormat }
                purpose = .signature(namespace: namespace)
            default:
                throw OpenSSHReaderError.incorrectFormat
            }
        }

        /// The extension contents, without the extension name.
        public var encoded: Data {
            var kind = "", host = "", user = "", namespace = ""
            var port: UInt32 = 0
            switch purpose {
            case .login(let h, let p, let u):
                (kind, host, port, user) = ("login", h, p, u)
            case .signature(let n):
                (kind, namespace) = ("sign", n)
            }
            var data = keyBlob.lengthAndData
            for string in [kind, host] {
                data.append(Data(string.utf8).lengthAndData)
            }
            data.append(Data.bigEndian(port))
            for string in [user, namespace] {
                data.append(Data(string.utf8).lengthAndData)
            }
            data.append(Data.bigEndian(seconds))
            data.append(Data(reason.utf8).lengthAndData)
            return data
        }

        /// No control characters, so the window cannot be confused by line breaks or escape sequences.
        static func isPrintable(_ string: String) -> Bool {
            !string.unicodeScalars.contains { $0.properties.generalCategory == .control || $0.properties.generalCategory == .format }
        }
    }

}
