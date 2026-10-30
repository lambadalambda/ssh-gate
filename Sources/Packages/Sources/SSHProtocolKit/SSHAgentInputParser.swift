import Foundation
import OSLog
import SecretKit
import CertificateKit

import CryptoKit

public protocol SSHAgentInputParserProtocol {

    func parse(data: Data) async throws -> SSHAgent.Request

}

public struct SSHAgentInputParser: SSHAgentInputParserProtocol {

    private let logger = Logger(subsystem: "com.maxgoedjen.secretive.secretagent", category: "InputParser")

    public init() {
        assert(Bundle.main.bundleURL.pathExtension == "xpc" || ProcessInfo.processInfo.processName == "xctest", "Potentially unsafe parsing code should run in an XPC service")
    }

    public func parse(data: Data) throws(AgentParsingError) -> SSHAgent.Request {
        logger.debug("Parsing new data")
        guard data.count > 4 else {
            throw .invalidData
        }
        let specifiedLength = unsafe (data[0..<4].bytes.unsafeLoad(as: UInt32.self).bigEndian) + 4
        let rawRequestInt = data[4]
        let remainingDataRange = 5..<min(Int(specifiedLength), data.count)
        lazy var body: Data = { Data(data[remainingDataRange]) }()
        switch rawRequestInt {
        case SSHAgent.Request.requestIdentities.protocolID:
            return .requestIdentities
        case SSHAgent.Request.signRequest(.empty).protocolID:
            do {
                return .signRequest(try signatureRequestContext(from: body))
            } catch {
                throw .openSSHReader(error)
            }
        case SSHAgent.Request.addIdentity.protocolID:
            return .addIdentity
        case SSHAgent.Request.removeIdentity.protocolID:
            return .removeIdentity
        case SSHAgent.Request.removeAllIdentities.protocolID:
            return .removeAllIdentities
        case SSHAgent.Request.addIDConstrained.protocolID:
            return .addIDConstrained
        case SSHAgent.Request.addSmartcardKey.protocolID:
            return .addSmartcardKey
        case SSHAgent.Request.removeSmartcardKey.protocolID:
            return .removeSmartcardKey
        case SSHAgent.Request.lock.protocolID:
            return .lock
        case SSHAgent.Request.unlock.protocolID:
            return .unlock
        case SSHAgent.Request.addSmartcardKeyConstrained.protocolID:
            return .addSmartcardKeyConstrained
        case SSHAgent.Request.protocolExtension(.empty).protocolID:
            return .protocolExtension(try protocolExtension(from: body))
        default:
            return .unknown(rawRequestInt)
        }
    }

}

extension SSHAgentInputParser {

    private enum Constants {
        static let userAuthMagic: UInt8 = 50 // SSH2_MSG_USERAUTH_REQUEST
        static let connectionService = "ssh-connection"
        static let publicKeyMethod = "publickey"
        static let hostboundMethod = "publickey-hostbound-v00@openssh.com"
        static let maxSessionIDLength = 64 // SSH_DIGEST_MAX_LENGTH
        static let sshSigMagic = Data("SSHSIG".utf8)
    }

    func signatureRequestContext(from data: Data) throws(OpenSSHReaderError) -> SSHAgent.Request.SignatureRequestContext {
        let reader = OpenSSHReader(data: data)
        let rawKeyBlob = try reader.readNextChunk()
        let keyBlob = certificatePublicKeyBlob(from: rawKeyBlob) ?? rawKeyBlob
        let rawPayload = try reader.readNextChunk()
        let payload: SSHAgent.Request.SignatureRequestContext.SignaturePayload
        do {
            if rawPayload.count > 6 && rawPayload[0..<6] == Constants.sshSigMagic {
                payload = .init(raw: rawPayload, decoded: .sshSig(try sshSigPayload(from: rawPayload[6...])))
            } else {
                payload = .init(raw: rawPayload, decoded: .sshConnection(try sshConnectionPayload(from: rawPayload)))
            }
        } catch {
            payload = .init(raw: rawPayload, decoded: nil)
        }
        return SSHAgent.Request.SignatureRequestContext(keyBlob: keyBlob, dataToSign: payload)
    }

    func sshSigPayload(from data: Data) throws(OpenSSHReaderError) -> SSHAgent.Request.SignatureRequestContext.SignaturePayload.DecodedPayload.SSHSigPayload {
        // https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig#L79
        let payloadReader = OpenSSHReader(data: data)
        let namespace = try payloadReader.readNextChunkAsString()
        _ = try payloadReader.readNextChunk() // reserved
        let hashAlgorithm = try payloadReader.readNextChunkAsString()
        let hash = try payloadReader.readNextChunk()
        return .init(
            namespace: namespace,
            hashAlgorithm: hashAlgorithm,
            hash: hash
        )
    }

    /// Parses the data that ssh signs for public key authentication (RFC 4252 section 7, and the OpenSSH
    /// publickey-hostbound-v00@openssh.com method). Anything unexpected is an error.
    func sshConnectionPayload(from data: Data) throws(OpenSSHReaderError) -> SSHAgent.Request.SignatureRequestContext.SignaturePayload.DecodedPayload.SSHConnectionPayload {
        let payloadReader = OpenSSHReader(data: data)
        let sessionID = try payloadReader.readNextChunk()
        guard !sessionID.isEmpty, sessionID.count <= Constants.maxSessionIDLength else { throw .incorrectFormat }
        let magic = try payloadReader.readNextBytes(as: UInt8.self, convertEndianness: false)
        guard magic == Constants.userAuthMagic else { throw .incorrectFormat }
        let username = try payloadReader.readNextChunkAsString()
        guard try payloadReader.readNextChunkAsString() == Constants.connectionService else { throw .incorrectFormat }
        let method = try payloadReader.readNextChunkAsString()
        guard try payloadReader.readNextBytes(as: UInt8.self, convertEndianness: false) == 1 else { throw .incorrectFormat }
        let algorithm = try payloadReader.readNextChunkAsString()
        let publicKey = try payloadReader.readNextChunk()
        guard Self.algorithm(algorithm, matchesKeyType: try OpenSSHReader(data: publicKey).readNextChunkAsString()) else {
            throw .incorrectFormat
        }
        let hostKey: Data?
        switch method {
        case Constants.publicKeyMethod:
            hostKey = nil
        case Constants.hostboundMethod:
            let presentedKey = try payloadReader.readNextChunk()
            if HostCertificate.isCertificate(presentedKey) {
                guard let certificate = try? HostCertificate(presentedKey) else { throw .incorrectFormat }
                hostKey = certificate.publicKey
            } else {
                hostKey = presentedKey
            }
        default:
            throw .incorrectFormat
        }
        guard payloadReader.done else { throw .incorrectFormat }
        return .init(
            sessionID: sessionID,
            username: username,
            hasSignature: true,
            publicKeyAlgorithm: algorithm,
            publicKey: publicKey,
            hostKey: hostKey
        )
    }

    /// Whether a userauth signature algorithm belongs to a key type. RSA keys sign with rsa-sha2-256 and rsa-sha2-512.
    static func algorithm(_ algorithm: String, matchesKeyType keyType: String) -> Bool {
        var normalized = algorithm
        for prefix in ["rsa-sha2-256", "rsa-sha2-512"] where normalized.hasPrefix(prefix) {
            normalized = "ssh-rsa" + normalized.dropFirst(prefix.count)
        }
        return normalized == keyType
    }

    func protocolExtension(from data: Data) throws(AgentParsingError) -> SSHAgent.ProtocolExtension {
        do {
            let reader = OpenSSHReader(data: data)
            let nameRaw = try reader.readNextChunkAsString()
            if nameRaw == SSHAgent.ProtocolExtension.GrantRequestContext.name {
                do {
                    return .grantRequest(try SSHAgent.ProtocolExtension.GrantRequestContext(reading: reader))
                } catch {
                    throw AgentParsingError.invalidData
                }
            }
            let nameSplit = nameRaw.split(separator: "@")
            guard nameSplit.count == 2 else {
                throw AgentParsingError.invalidData
            }
            let (name, domain) = (nameSplit[0], nameSplit[1])
            switch domain {
            case SSHAgent.ProtocolExtension.OpenSSHExtension.domain:
                switch name {
                case SSHAgent.ProtocolExtension.OpenSSHExtension.sessionBind(.empty).name:
                    // https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.agent
                    let presentedKey = try reader.readNextChunk()
                    let sessionID = try reader.readNextChunk()
                    let signature = try reader.readNextChunk()
                    let forwarding = try reader.readNextByteAsBool()
                    guard reader.done, !sessionID.isEmpty, sessionID.count <= Constants.maxSessionIDLength else {
                        throw AgentParsingError.invalidData
                    }
                    let certificate: HostCertificate?
                    let hostKey: Data
                    do {
                        certificate = HostCertificate.isCertificate(presentedKey) ? try HostCertificate(presentedKey) : nil
                        hostKey = certificate?.publicKey ?? presentedKey
                        try HostKeySignatureVerifier.verify(hostKey: hostKey, signature: signature, data: sessionID)
                    } catch {
                        throw AgentParsingError.incorrectSignature
                    }
                    return .openSSH(.sessionBind(.init(
                        hostKey: hostKey,
                        sessionID: sessionID,
                        signature: signature,
                        forwarding: forwarding,
                        certificate: certificate
                    )))
                default:
                    return .openSSH(.unknown(String(name)))
                }
            default:
                return .unknown(nameRaw)
            }

        } catch let error as OpenSSHReaderError {
            throw .openSSHReader(error)
        } catch let error as AgentParsingError {
            throw error
        } catch {
            throw .unknownRequest
        }
    }

    func certificatePublicKeyBlob(from hash: Data) -> Data? {
        HostCertificate.plainPublicKey(ofCertificate: hash)
    }

}


extension SSHAgentInputParser {

    public enum AgentParsingError: Error, Codable {
        case unknownRequest
        case unhandledRequest
        case invalidData
        case incorrectSignature
        case openSSHReader(OpenSSHReaderError)
    }

}
