import Foundation

/// An OpenSSH host certificate (PROTOCOL.certkeys) whose CA signature is valid.
///
/// The agent does not decide whether the CA is trusted; ssh already checked the certificate against known_hosts. It
/// uses the certificate to find the plain host key inside it, and the CA key to look up whether known_hosts trusts the
/// CA before it shows the principals.
public struct HostCertificate: Sendable, Codable, Equatable {

    /// The plain public key blob inside the certificate.
    public let publicKey: Data
    public let principals: [String]
    /// The CA's public key blob.
    public let authority: Data
    /// Seconds since 1970; ssh checked them, the agent uses them only to decide whether to show the principals.
    public let validAfter: UInt64
    public let validBefore: UInt64

    static let suffix = "-cert-v01@openssh.com"
    static let hostType: UInt32 = 2

    /// Plain key types and how many public key fields their certificates carry.
    static let keyFieldCount: [String: Int] = [
        "ssh-ed25519": 1,
        "ecdsa-sha2-nistp256": 2,
        "ecdsa-sha2-nistp384": 2,
        "ecdsa-sha2-nistp521": 2,
        "ssh-rsa": 2,
    ]

    /// Note: the synthesized `Decodable` does not verify anything. Decoded values come from the agent's own XPC parser.
    public func isValid(at date: Date) -> Bool {
        let now = date.timeIntervalSince1970
        return now >= Double(validAfter) && now < Double(validBefore)
    }

    static func plainType(of certType: String) -> String? {
        certType.hasSuffix(suffix) ? String(certType.dropLast(suffix.count)) : nil
    }

    /// The plain public key blob inside any certificate (user or host) of a supported key type. Does not verify it.
    public static func plainPublicKey(ofCertificate blob: Data) -> Data? {
        guard let fields = try? Fields(blob) else { return nil }
        var publicKey = Data(fields.plainType.utf8).lengthAndData
        for field in fields.keyFields {
            publicKey.append(field.lengthAndData)
        }
        return publicKey
    }

    public static func isCertificate(_ blob: Data) -> Bool {
        (try? OpenSSHReader(data: blob).readNextChunkAsString())?.hasSuffix(suffix) ?? false
    }

    public init(_ blob: Data) throws {
        let fields = try Fields(blob)
        guard fields.type == Self.hostType, !Self.isCertificate(fields.signatureKey) else {
            throw OpenSSHReaderError.incorrectFormat
        }
        let signed = blob.prefix(blob.count - 4 - fields.signature.count)
        try HostKeySignatureVerifier.verify(hostKey: fields.signatureKey, signature: fields.signature, data: Data(signed))

        let publicKey = Self.plainPublicKey(ofCertificate: blob)!
        let principalReader = OpenSSHReader(data: fields.principals)
        var principals: [String] = []
        while !principalReader.done {
            principals.append(try principalReader.readNextChunkAsString())
        }
        self.publicKey = publicKey
        self.principals = principals
        self.authority = fields.signatureKey
        self.validAfter = fields.validAfter
        self.validBefore = fields.validBefore
    }

    /// The raw fields of a certificate, in wire order.
    struct Fields {
        var certType: String
        var nonce: Data
        var keyFields: [Data]
        var serial: UInt64
        var type: UInt32
        var keyID: Data
        var principals: Data
        var validAfter: UInt64
        var validBefore: UInt64
        var criticalOptions: Data
        var extensions: Data
        var reserved: Data
        var signatureKey: Data
        var signature: Data

        let plainType: String

        init(_ blob: Data) throws {
            let reader = OpenSSHReader(data: blob)
            certType = try reader.readNextChunkAsString()
            guard let plain = HostCertificate.plainType(of: certType), let count = HostCertificate.keyFieldCount[plain] else {
                throw OpenSSHReaderError.incorrectFormat
            }
            plainType = plain
            nonce = try reader.readNextChunk()
            keyFields = try (0..<count).map { _ in try reader.readNextChunk() }
            serial = try reader.readNextBytes(as: UInt64.self)
            type = try reader.readNextBytes(as: UInt32.self)
            keyID = try reader.readNextChunk()
            principals = try reader.readNextChunk()
            validAfter = try reader.readNextBytes(as: UInt64.self)
            validBefore = try reader.readNextBytes(as: UInt64.self)
            criticalOptions = try reader.readNextChunk()
            extensions = try reader.readNextChunk()
            reserved = try reader.readNextChunk()
            signatureKey = try reader.readNextChunk()
            signature = try reader.readNextChunk()
            guard reader.done else { throw OpenSSHReaderError.incorrectFormat }
        }
    }

}
