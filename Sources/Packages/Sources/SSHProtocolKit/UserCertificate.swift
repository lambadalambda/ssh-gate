import Foundation

/// Builds OpenSSH user certificates (PROTOCOL.certkeys) for grants.
public enum UserCertificate {

    static let userType: UInt32 = 1

    /// Whether a user name is safe as a certificate principal. sshd splits principals at commas when it matches them
    /// against `principals="..."` in authorized_keys, and patterns could widen them.
    public static func isSafePrincipal(_ name: String) -> Bool {
        !name.isEmpty && !name.unicodeScalars.contains {
            $0.properties.isWhitespace || $0.properties.generalCategory == .control || ",*?!\"".unicodeScalars.contains($0)
        }
    }

    /// Extensions as ssh-keygen sets them by default, without agent and X11 forwarding: grants refuse forwarded
    /// agents anyway. Sorted by name, as the format requires.
    static let extensions = ["permit-port-forwarding", "permit-pty", "permit-user-rc"]

    public struct Request: Sendable {
        /// The plain public key blob that the certificate is for.
        public let publicKey: Data
        public let serial: UInt64
        public let keyID: String
        public let principals: [String]
        /// Seconds since 1970.
        public let validAfter: UInt64
        public let validBefore: UInt64
        /// The CA's public key blob.
        public let authority: Data

        public init(publicKey: Data, serial: UInt64, keyID: String, principals: [String], validAfter: UInt64, validBefore: UInt64, authority: Data) {
            self.publicKey = publicKey
            self.serial = serial
            self.keyID = keyID
            self.principals = principals
            self.validAfter = validAfter
            self.validBefore = validBefore
            self.authority = authority
        }

        /// The certificate up to and including the CA key: the data the CA signs.
        public func toBeSigned(nonce: Data) throws -> Data {
            let keyReader = OpenSSHReader(data: publicKey)
            let keyType = try keyReader.readNextChunkAsString()
            guard let count = HostCertificate.keyFieldCount[keyType] else { throw OpenSSHReaderError.incorrectFormat }
            let keyFields = try (0..<count).map { _ in try keyReader.readNextChunk() }
            guard keyReader.done else { throw OpenSSHReaderError.incorrectFormat }

            var data = Data((keyType + HostCertificate.suffix).utf8).lengthAndData
            data.append(nonce.lengthAndData)
            for field in keyFields {
                data.append(field.lengthAndData)
            }
            data.append(Data.bigEndian(serial))
            data.append(Data.bigEndian(UserCertificate.userType))
            data.append(Data(keyID.utf8).lengthAndData)
            data.append(principals.reduce(into: Data()) { $0.append(Data($1.utf8).lengthAndData) }.lengthAndData)
            data.append(Data.bigEndian(validAfter))
            data.append(Data.bigEndian(validBefore))
            data.append(Data().lengthAndData) // critical options
            let extensions = UserCertificate.extensions.reduce(into: Data()) {
                $0.append(Data($1.utf8).lengthAndData)
                $0.append(Data().lengthAndData)
            }
            data.append(extensions.lengthAndData)
            data.append(Data().lengthAndData) // reserved
            data.append(authority.lengthAndData)
            return data
        }
    }

    /// The complete certificate blob.
    /// - Parameter signature: The CA's signature blob (`string algorithm, string signature`) over `toBeSigned`.
    public static func assemble(toBeSigned: Data, signature: Data) -> Data {
        toBeSigned + signature.lengthAndData
    }

}
