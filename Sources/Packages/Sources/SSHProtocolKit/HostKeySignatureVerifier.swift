import Foundation
import CryptoKit
import Security

/// Verifies a signature made by an SSH host key, as in a session-bind@openssh.com message.
public enum HostKeySignatureVerifier {

    public enum VerificationError: Error, Codable {
        case unsupportedKeyType
        case keyTypeMismatch
        case invalidKey
        case invalidSignature
    }

    /// - Parameters:
    ///   - hostKey: The full host key blob (`string type, ...`).
    ///   - signature: The full signature blob (`string algorithm, string signature`).
    ///   - data: The signed data, e.g. the session ID.
    /// - Throws: If the blobs are malformed, do not belong together, or the signature is invalid.
    public static func verify(hostKey: Data, signature: Data, data: Data) throws {
        let keyReader = OpenSSHReader(data: hostKey)
        let keyType = try keyReader.readNextChunkAsString()
        let signatureReader = OpenSSHReader(data: signature)
        let algorithm = try signatureReader.readNextChunkAsString()
        let rawSignature = try signatureReader.readNextChunk()
        guard signatureReader.done else { throw OpenSSHReaderError.incorrectFormat }

        let valid: Bool
        switch keyType {
        case "ssh-ed25519":
            guard algorithm == keyType else { throw VerificationError.keyTypeMismatch }
            let key = try Curve25519.Signing.PublicKey(rawRepresentation: try keyReader.readNextChunk())
            try requireEnd(keyReader)
            valid = key.isValidSignature(rawSignature, for: data)
        case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
            guard algorithm == keyType else { throw VerificationError.keyTypeMismatch }
            let curve = try keyReader.readNextChunkAsString()
            guard keyType == "ecdsa-sha2-" + curve else { throw VerificationError.invalidKey }
            let point = try keyReader.readNextChunk()
            try requireEnd(keyReader)
            valid = try verifyECDSA(curve: curve, point: point, signature: rawSignature, data: data)
        case "ssh-rsa":
            guard let secAlgorithm = rsaAlgorithms[algorithm] else { throw VerificationError.keyTypeMismatch }
            let exponent = try keyReader.readNextChunk()
            let modulus = try keyReader.readNextChunk()
            try requireEnd(keyReader)
            valid = try verifyRSA(exponent: exponent, modulus: modulus, algorithm: secAlgorithm, signature: rawSignature, data: data)
        case "ssh-mldsa-65", "ssh-mldsa-87":
            guard algorithm == keyType else { throw VerificationError.keyTypeMismatch }
            let rawKey = try keyReader.readNextChunk()
            try requireEnd(keyReader)
            valid = try verifyMLDSA(keyType: keyType, rawKey: rawKey, signature: rawSignature, data: data)
        default:
            throw VerificationError.unsupportedKeyType
        }
        guard valid else { throw VerificationError.invalidSignature }
    }

    /// RSA host keys sign with SHA-2 only. OpenSSH no longer uses SHA-1 ("ssh-rsa") signatures by default.
    static let rsaAlgorithms: [String: SecKeyAlgorithm] = [
        "rsa-sha2-256": .rsaSignatureMessagePKCS1v15SHA256,
        "rsa-sha2-512": .rsaSignatureMessagePKCS1v15SHA512,
    ]

    /// OpenSSH's SSH_RSA_MINIMUM_MODULUS_SIZE.
    static let minimumRSABits = 1024

    static func requireEnd(_ reader: OpenSSHReader) throws {
        guard reader.done else { throw OpenSSHReaderError.incorrectFormat }
    }

    static func verifyECDSA(curve: String, point: Data, signature: Data, data: Data) throws -> Bool {
        // The signature is `mpint r, mpint s`; CryptoKit wants r and s as fixed-size big-endian integers.
        let reader = OpenSSHReader(data: signature)
        let r = try reader.readNextChunk()
        let s = try reader.readNextChunk()
        try requireEnd(reader)
        switch curve {
        case "nistp256":
            let key = try P256.Signing.PublicKey(x963Representation: point)
            let raw = try fixedWidth(r, 32) + fixedWidth(s, 32)
            return key.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: raw), for: data)
        case "nistp384":
            let key = try P384.Signing.PublicKey(x963Representation: point)
            let raw = try fixedWidth(r, 48) + fixedWidth(s, 48)
            return key.isValidSignature(try P384.Signing.ECDSASignature(rawRepresentation: raw), for: data)
        case "nistp521":
            let key = try P521.Signing.PublicKey(x963Representation: point)
            let raw = try fixedWidth(r, 66) + fixedWidth(s, 66)
            return key.isValidSignature(try P521.Signing.ECDSASignature(rawRepresentation: raw), for: data)
        default:
            throw VerificationError.unsupportedKeyType
        }
    }

    static func verifyRSA(exponent: Data, modulus: Data, algorithm: SecKeyAlgorithm, signature: Data, data: Data) throws -> Bool {
        let n = try unsignedMPInt(modulus)
        let e = try unsignedMPInt(exponent)
        guard bitCount(n) >= minimumRSABits, !e.isEmpty else { throw VerificationError.invalidKey }
        // PKCS#1 RSAPublicKey: SEQUENCE { INTEGER n, INTEGER e }
        let der = derSequence(derInteger(n) + derInteger(e))
        let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPublic]
        guard let key = SecKeyCreateWithData(der as CFData, attributes as CFDictionary, nil) else {
            throw VerificationError.invalidKey
        }
        return SecKeyVerifySignature(key, algorithm, data as CFData, signature as CFData, nil)
    }

    static func verifyMLDSA(keyType: String, rawKey: Data, signature: Data, data: Data) throws -> Bool {
        guard #available(macOS 26.0, *) else { throw VerificationError.unsupportedKeyType }
        switch keyType {
        case "ssh-mldsa-65":
            return try MLDSA65.PublicKey(rawRepresentation: rawKey).isValidSignature(signature, for: data)
        default:
            return try MLDSA87.PublicKey(rawRepresentation: rawKey).isValidSignature(signature, for: data)
        }
    }

    static func stripLeadingZeros(_ data: Data) -> Data {
        Data(data.drop { $0 == 0 })
    }

    /// The magnitude of a non-negative SSH mpint (RFC 4251 section 5). Like OpenSSH, refuses negative and
    /// non-minimal encodings, so one number has exactly one encoding.
    static func unsignedMPInt(_ value: Data) throws -> Data {
        guard let first = value.first else { return Data() }
        guard first & 0x80 == 0 else { throw VerificationError.invalidSignature }
        if first == 0 {
            guard value.count > 1, value[value.startIndex + 1] & 0x80 != 0 else { throw VerificationError.invalidSignature }
            return Data(value.dropFirst())
        }
        return Data(value)
    }

    /// The number of significant bits of an unsigned big-endian integer without leading zero bytes.
    static func bitCount(_ magnitude: Data) -> Int {
        guard let first = magnitude.first else { return 0 }
        return (magnitude.count - 1) * 8 + (8 - first.leadingZeroBitCount)
    }

    /// Converts an SSH mpint to exactly `width` unsigned big-endian bytes.
    static func fixedWidth(_ value: Data, _ width: Int) throws -> Data {
        let stripped = try unsignedMPInt(value)
        guard stripped.count <= width else { throw VerificationError.invalidSignature }
        return Data(repeating: 0, count: width - stripped.count) + stripped
    }

    static func derLength(_ count: Int) -> Data {
        if count < 0x80 {
            return Data([UInt8(count)])
        }
        var bytes = Data()
        var n = count
        while n > 0 {
            bytes.insert(UInt8(n & 0xff), at: 0)
            n >>= 8
        }
        return Data([0x80 | UInt8(bytes.count)]) + bytes
    }

    static func derInteger(_ value: Data) -> Data {
        var content = stripLeadingZeros(value)
        if content.isEmpty || content.first! & 0x80 != 0 {
            content.insert(0, at: 0)
        }
        return Data([0x02]) + derLength(content.count) + content
    }

    static func derSequence(_ content: Data) -> Data {
        Data([0x30]) + derLength(content.count) + content
    }

}
