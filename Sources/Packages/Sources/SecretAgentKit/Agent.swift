import Foundation
import CryptoKit
import OSLog
import SecretKit
import CertificateKit
import AppKit
import SSHProtocolKit
import Synchronization

/// The `Agent` is an implementation of an SSH agent. It manages coordination and access between a socket, traces requests, notifies witnesses and passes requests to stores.
public final class Agent: Sendable {

    private let storeList: SecretStoreList
    private let authenticationHandler: AuthenticationHandler
    private let certificateStore: CertificateStore
    private let witness: SigningWitness?
    private let grantApprover: GrantApprover?
    private let grants = Mutex(GrantSet())
    private let now: @Sendable () -> Date
    private let publicKeyWriter = OpenSSHPublicKeyWriter()
    private let signatureWriter = OpenSSHSignatureWriter()
    private let logger = Logger(subsystem: "com.maxgoedjen.secretive.secretagent", category: "Agent")

    /// Initializes an agent with a store list and a witness.
    /// - Parameters:
    ///   - storeList: The `SecretStoreList` to make available.
    ///   - witness: A witness to notify of requests.
    ///   - grantApprover: If set, every signature needs a matching grant or the approver's decision.
    ///   - now: The wall clock for grant expiry.
    public init(
        storeList: SecretStoreList,
        certificateStore: CertificateStore,
        authenticationHandler: AuthenticationHandler,
        witness: SigningWitness? = nil,
        grantApprover: GrantApprover? = nil,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        logger.debug("Agent is running")
        self.storeList = storeList
        self.certificateStore = certificateStore
        self.authenticationHandler = authenticationHandler
        self.witness = witness
        self.grantApprover = grantApprover
        self.now = now
    }
    
}

extension Agent {

    public func handle(
        request: SSHAgent.Request,
        provenance: SigningRequestProvenance,
        hosts: KnownHosts?,
        connection: AgentConnection
    ) async -> Data {
        logger.debug("Agent received request of type \(request.debugDescription)")
        // Depending on the launch context (such as after macOS update), the agent may need to reload secrets before acting
        await reloadSecretsIfNeccessary()
        var response = Data()
        do {
            switch request {
            case .requestIdentities:
                response.append(SSHAgent.Response.agentIdentitiesAnswer.data)
                response.append(await identities())
                logger.debug("Agent returned \(SSHAgent.Response.agentIdentitiesAnswer.debugDescription)")
            case .signRequest(let context):
                let state = connection.snapshot
                if let reason = state.poisoned {
                    logger.error("Agent refused request on poisoned connection: \(reason, privacy: .public)")
                    throw BindingFailure()
                }
                let purpose = AgentConnection.purpose(of: context.dataToSign.decoded, in: state)
                let grantContext = GrantContext(
                    purpose: purpose,
                    forwarded: state.forwarded,
                    host: Self.hostName(for: purpose, bind: state.bind, knownHosts: hosts, now: now())
                )
                let target: SigningRequestTarget?
                switch context.dataToSign.decoded {
                case .sshConnection(let payload):
                    target = .connection(
                        .init(
                            username: payload.username,
                            hasSignature: payload.hasSignature,
                            publicKeyAlgorithm: payload.publicKeyAlgorithm,
                            publicKey: payload.publicKey,
                            hostKey: payload.hostKey ?? Data(),
                            host: grantContext.host
                        )
                    )
                case .sshSig(let payload):
                    target = .signature(
                        .init(
                            namespace: payload.namespace,
                            hashAlgorithm: payload.hashAlgorithm,
                            hash: payload.hash
                        )
                    )
                default:
                    target = nil
                }
                response.append(SSHAgent.Response.agentSignResponse.data)
                response.append(try await sign(data: context.dataToSign.raw, keyBlob: context.keyBlob, provenance: provenance, target: target, grantContext: grantContext))
                logger.debug("Agent returned \(SSHAgent.Response.agentSignResponse.debugDescription)")
            case .protocolExtension(.openSSH(.sessionBind(let bind))):
                do {
                    try connection.bind(bind)
                } catch {
                    logger.error("Agent refused session-bind: \(String(describing: error), privacy: .public)")
                    throw BindingFailure()
                }
                response = SSHAgent.Response.agentSuccess.data
                logger.debug("Agent returned \(SSHAgent.Response.agentSuccess.debugDescription)")
            case .unknown(let value):
                logger.error("Agent received unknown request of type \(value).")
                throw UnhandledRequestError()
            default:
                logger.debug("Agent received valid request of type \(request.debugDescription), but not currently supported.")
                throw UnhandledRequestError()
            }
        } catch {
            response = SSHAgent.Response.agentFailure.data
            logger.debug("Agent returned \(SSHAgent.Response.agentFailure.debugDescription)")
        }
        return response.lengthAndData
    }

}

extension Agent {

    /// Lists the identities available for signing operations
    /// - Returns: An OpenSSH formatted Data payload listing the identities available for signing operations.
    func identities() async -> Data {
        let secrets = await storeList.allSecrets
        var count = 0
        var keyData = Data()

        for secret in secrets {
            let keyBlob = publicKeyWriter.data(secret: secret)
            keyData.append(keyBlob.lengthAndData)
            keyData.append(publicKeyWriter.comment(secret: secret).lengthAndData)
            count += 1
            for certificate in await certificateStore.certificates(for: secret) {
                keyData.append(certificate.data.lengthAndData)
                keyData.append(certificate.name.lengthAndData)
                count += 1
            }
        }
        logger.log("Agent enumerated \(count) identities")
        var countBigEndian = UInt32(count).bigEndian
        let countData = unsafe Data(bytes: &countBigEndian, count: MemoryLayout<UInt32>.size)
        return countData + keyData
    }

    /// Notifies witnesses of a pending signature request, and performs the signing operation if none object.
    /// - Parameters:
    ///   - data: The data to sign.
    ///   - provenance: A ``SecretKit.SigningRequestProvenance`` object describing the origin of the request.
    /// - Returns: An OpenSSH formatted Data payload containing the signed data response.
    func sign(data: Data, keyBlob: Data, provenance: SigningRequestProvenance, target: SigningRequestTarget?, grantContext: GrantContext) async throws -> Data {
        guard let (secret, store) = await secret(matching: keyBlob) else {
            let keyBlobHex = keyBlob.formatted(.hex())
            logger.debug("Agent did not have a key matching \(keyBlobHex)")
            throw NoMatchingKeyError()
        }
        try await authorize(secret: secret, keyBlob: keyBlob, provenance: provenance, context: grantContext)
        logger.debug("Agent offering witness chance to object")
        do {
            try await witness?.speakNowOrForeverHoldYourPeace(forAccessTo: secret, from: store, by: provenance, target: target)
        } catch {
            logger.debug("Witness objected")
            throw error
        }
        logger.debug("Witness did not object")

        let request = SignatureRequest(secret: secret, provenance: provenance, target: target)
        let newContext = AuthenticationContext(secret: secret, requests: [request])
        let context = try await authenticationHandler.authenticatedContext(for: request, context: newContext)
        let result = try await store.sign(data: data, with: secret, for: provenance, target: target, context: context?.laContext)
        let signedData = signatureWriter.data(secret: secret, signature: result)
        try await witness?.witness(accessTo: secret, from: store, by: provenance, target: target, offerPersistence: secret.authenticationRequirement.required)
        logger.debug("Agent signed request")
        return signedData
    }

}

extension Agent {

    /// The host name to show for a login: the known_hosts name of the host key, or, for a valid host certificate
    /// whose CA known_hosts trusts, the certificate's principals that the CA line's patterns allow. Never principals of
    /// an unknown CA, which anybody can write.
    static func hostName(for purpose: GrantPurpose?, bind: AgentConnection.SessionBind?, knownHosts: KnownHosts?, now: Date) -> String? {
        guard case .login(_, let hostKey) = purpose, let knownHosts else { return nil }
        if let name = knownHosts.names[hostKey] {
            return name
        }
        guard let certificate = bind?.certificate, certificate.publicKey == hostKey, certificate.isValid(at: now),
              let patterns = knownHosts.authorities[certificate.authority] else {
            return nil
        }
        let allowed = certificate.principals.filter { HostPattern.matches($0, patterns: patterns) }
        return allowed.isEmpty ? nil : allowed.joined(separator: ", ")
    }

}

struct GrantContext {
    let purpose: GrantPurpose?
    let forwarded: Bool
    let host: String?
}

extension Agent {

    struct GrantDenied: Error {}

    /// Lets a request through if a grant covers it, else asks the grant approver. Does nothing without an approver.
    func authorize(secret: AnySecret, keyBlob: Data, provenance: SigningRequestProvenance, context: GrantContext) async throws {
        guard let grantApprover else { return }
        if let purpose = context.purpose,
           let grant = grants.withLock({ $0.match(publicKey: keyBlob, chain: provenance.chain, purpose: purpose, now: now()) }) {
            logger.debug("Grant \(grant.id, privacy: .public) covers request")
            return
        }
        let request = GrantRequest(
            secret: secret,
            provenance: provenance,
            purpose: context.purpose,
            host: context.host,
            defaultRequesterIndex: context.purpose == nil ? nil : RequesterSelection.defaultIndex(in: provenance.chain),
            forwarded: context.forwarded
        )
        switch await grantApprover.decide(request) {
        case .deny:
            logger.debug("Grant approver denied request")
            throw GrantDenied()
        case .once:
            logger.debug("Grant approver allowed request once")
        case .grant(let index, let duration):
            guard let purpose = context.purpose, duration > 0, duration.isFinite,
                  provenance.chain.indices.contains(index),
                  let requester = GrantRequester(process: provenance.chain[index]) else {
                logger.debug("Grant approver allowed request, but no grant is possible; allowed once")
                return
            }
            let start = now()
            grants.withLock {
                $0.removeExpired(now: start)
                $0.add(Grant(publicKey: keyBlob, requester: requester, purpose: purpose, expires: start + duration))
            }
            logger.debug("Grant approver created grant for \(requester.path, privacy: .public)")
        }
    }

}

extension Agent {

    /// Gives any store with no loaded secrets a chance to reload.
    func reloadSecretsIfNeccessary() async {
        for store in await storeList.stores {
            if await store.secrets.isEmpty {
                let name = await store.name
                logger.debug("Store \(name, privacy: .public) has no loaded secrets. Reloading.")
                await store.reloadSecrets()
            }
        }
    }

    /// Finds a ``Secret`` matching a specified hash whos signature was requested.
    /// - Parameter hash: The hash to match against.
    /// - Returns: A ``Secret`` and the ``SecretStore`` containing it, if a match is found.
    func secret(matching hash: Data) async -> (AnySecret, AnySecretStore)? {
        await storeList.allSecretsWithStores.first {
            hash == publicKeyWriter.data(secret: $0.0)
        }
    }

}


extension Agent {

    struct NoMatchingKeyError: Error {}
    struct UnhandledRequestError: Error {}
    struct BindingFailure: Error {}

}

extension SSHAgent.Response {

    var data: Data {
        var raw = self.rawValue
        return unsafe Data(bytes: &raw, count: MemoryLayout<UInt8>.size)
    }

}
