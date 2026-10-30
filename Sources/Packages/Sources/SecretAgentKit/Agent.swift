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
    /// Requests in advance that were denied, by requester and purpose, until when they are refused without asking.
    private let deniedAdvance = Mutex([String: Date]())
    static let advanceDenialPause: TimeInterval = 30
    private let now: @Sendable () -> Date
    /// The public key blob of the secret that signs grant certificates, if one is set.
    private let certificateAuthority: @Sendable () async -> Data?
    private let issuedCertificates = Mutex([IssuedCertificate]())
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
        now: @escaping @Sendable () -> Date = { Date() },
        certificateAuthority: @escaping @Sendable () async -> Data? = { nil }
    ) {
        logger.debug("Agent is running")
        self.storeList = storeList
        self.certificateStore = certificateStore
        self.authenticationHandler = authenticationHandler
        self.witness = witness
        self.grantApprover = grantApprover
        self.now = now
        self.certificateAuthority = certificateAuthority
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
            case .protocolExtension(.grantRequest(let context)):
                guard try await grantInAdvance(context, provenance: provenance, hosts: hosts, connection: connection) else {
                    throw GrantDenied()
                }
                response = SSHAgent.Response.agentSuccess.data
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
        let authority = await certificateAuthority()
        var count = 0
        var keyData = Data()

        for secret in secrets {
            let keyBlob = publicKeyWriter.data(secret: secret)
            // The grant CA only signs grant certificates; clients never see or use it.
            guard keyBlob != authority else { continue }
            keyData.append(keyBlob.lengthAndData)
            keyData.append(publicKeyWriter.comment(secret: secret).lengthAndData)
            count += 1
            for certificate in await certificateStore.certificates(for: secret) {
                keyData.append(certificate.data.lengthAndData)
                keyData.append(certificate.name.lengthAndData)
                count += 1
            }
        }
        let current = now()
        for certificate in issuedCertificates.withLock({ $0.filter { current < $0.expires } }) {
            keyData.append(certificate.blob.lengthAndData)
            keyData.append(certificate.comment.lengthAndData)
            count += 1
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
        guard await keyBlob != certificateAuthority() else {
            logger.error("Agent refused a client request to sign with the grant CA key")
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

struct IssuedCertificate: Sendable {
    let publicKey: Data
    let principals: [String]
    let blob: Data
    let comment: String
    let expires: Date
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
            guard let purpose = context.purpose, let added = addGrants(for: [purpose], keyBlob: keyBlob, provenance: provenance, requesterIndex: index, duration: duration) else {
                logger.debug("Grant approver allowed request, but no grant is possible; allowed once")
                return
            }
            await issueCertificate(for: [purpose], keyBlob: keyBlob, requester: added.requester, expires: added.expires, provenance: provenance)
        }
    }

    /// Adds one grant per purpose. Returns `nil` (and adds nothing) if no grant is possible.
    func addGrants(for purposes: [GrantPurpose], keyBlob: Data, provenance: SigningRequestProvenance, requesterIndex: Int, duration: TimeInterval) -> (requester: GrantRequester, expires: Date)? {
        guard !purposes.isEmpty, duration > 0, duration.isFinite,
              provenance.chain.indices.contains(requesterIndex),
              let requester = GrantRequester(process: provenance.chain[requesterIndex]) else {
            return nil
        }
        let start = now()
        let expires = start + duration
        grants.withLock { grants in
            grants.removeExpired(now: start)
            for purpose in purposes {
                grants.add(Grant(publicKey: keyBlob, requester: requester, purpose: purpose, expires: expires))
            }
        }
        logger.debug("Created \(purposes.count) grant(s) for \(requester.path, privacy: .public)")
        return (requester, expires)
    }

    /// For login grants, signs a user certificate with the grant CA, if one is set: principals are the granted users,
    /// valid until the grants expire, so servers that trust the CA enforce the expiry themselves. Failures only cost the
    /// certificate, not the grant.
    func issueCertificate(for purposes: [GrantPurpose], keyBlob: Data, requester: GrantRequester, expires: Date, provenance: SigningRequestProvenance) async {
        let users = purposes.reduce(into: [String]()) { users, purpose in
            if case .login(let user, _) = purpose, !users.contains(user) { users.append(user) }
        }
        guard !users.isEmpty, users.allSatisfy(UserCertificate.isSafePrincipal), let authority = await certificateAuthority(), authority != keyBlob,
              let (caSecret, caStore) = await secret(matching: authority) else {
            return
        }
        let start = now()
        let request = UserCertificate.Request(
            publicKey: keyBlob,
            serial: UInt64.random(in: 1...UInt64.max),
            keyID: "secretive grant: \(requester.path) pid \(requester.pid)",
            principals: users,
            validAfter: UInt64(max(0, start.timeIntervalSince1970 - 60)),
            validBefore: UInt64(expires.timeIntervalSince1970),
            authority: authority
        )
        do {
            let toBeSigned = try request.toBeSigned(nonce: Data((0..<32).map { _ in UInt8.random(in: 0...255) }))
            let raw = try await caStore.sign(data: toBeSigned, with: caSecret, for: provenance, target: nil, context: nil)
            let signature = try OpenSSHReader(data: signatureWriter.data(secret: caSecret, signature: raw)).readNextChunk()
            let blob = UserCertificate.assemble(toBeSigned: toBeSigned, signature: signature)
            let comment = "grant for \(users.joined(separator: ",")) until \(expires.formatted(date: .omitted, time: .shortened))"
            issuedCertificates.withLock {
                // A renewal replaces the earlier certificate for the same key and users.
                $0.removeAll { start >= $0.expires || ($0.publicKey == keyBlob && $0.principals == users) }
                $0.append(IssuedCertificate(publicKey: keyBlob, principals: users, blob: blob, comment: comment, expires: expires))
            }
            logger.debug("Issued grant certificate for \(users.joined(separator: ","), privacy: .public)")
        } catch {
            logger.error("Could not issue grant certificate: \(String(describing: error), privacy: .public)")
        }
    }

    /// Handles request-grant@heldscal.la: asks the approver for a grant before the key is used. Login requests name a
    /// host; its keys come from the agent's own reading of known_hosts, never from the client.
    func grantInAdvance(_ context: SSHAgent.ProtocolExtension.GrantRequestContext, provenance: SigningRequestProvenance, hosts: KnownHosts?, connection: AgentConnection) async throws -> Bool {
        let state = connection.snapshot
        // Only the request tool may ask in advance. Over an agent forwarded without session-bind, a remote host's
        // request would come from the local ssh process and look local.
        guard let grantApprover, state.poisoned == nil, !state.forwarded,
              provenance.chain.first.map(RequesterSelection.name(of:)) == "ssh-grant" else {
            return false
        }
        let defaultIndex = RequesterSelection.defaultIndex(in: provenance.chain)
        let pauseKey = Self.pauseKey(context, chain: provenance.chain, requesterIndex: defaultIndex)
        let start = now()
        if let until = deniedAdvance.withLock({ $0[pauseKey] }), start < until {
            logger.debug("Grant request refused: denied recently")
            return false
        }
        let authority = await certificateAuthority()
        let found = context.keyBlob.isEmpty ? await firstSecret(except: authority) : await secret(matching: context.keyBlob)
        guard let (secret, _) = found else { return false }
        let keyBlob = publicKeyWriter.data(secret: secret)
        guard keyBlob != authority else { return false }

        let purposes: [GrantPurpose]
        let host: String?
        switch context.purpose {
        case .login(let name, let port, let user):
            let matching = (hosts?.names ?? [:]).filter { HostPattern.matches(host: name, port: port, patterns: $0.value) }
            purposes = matching.keys.sorted { $0.lexicographicallyPrecedes($1) }.map { .login(username: user, hostKey: $0) }
            host = Self.displayHost(name: name, port: port, matchingPatterns: Array(matching.values))
        case .signature(let namespace):
            purposes = [.signature(namespace: namespace)]
            host = nil
        }
        guard let first = purposes.first else {
            logger.debug("Grant request for a host without known host keys refused")
            return false
        }
        // Already granted to this requester: answer without a window, so wrappers like `ssh-grant ssh` can ask before
        // every connection.
        let covered = grants.withLock { grants in
            purposes.allSatisfy { grants.match(publicKey: keyBlob, chain: provenance.chain, purpose: $0, now: start) != nil }
        }
        if covered {
            logger.debug("Grant request already covered by existing grants")
            return true
        }
        var request = GrantRequest(
            secret: secret,
            provenance: provenance,
            purpose: first,
            host: host,
            defaultRequesterIndex: defaultIndex,
            forwarded: false
        )
        request.advance = true
        request.reason = context.reason
        request.additionalPurposes = Array(purposes.dropFirst())
        request.requestedDuration = min(TimeInterval(context.seconds), GrantPresentation.maximumDuration)
        let decision = await grantApprover.decide(request)
        if decision == .deny {
            deniedAdvance.withLock {
                $0 = $0.filter { $0.value > start }
                $0[pauseKey] = now() + Self.advanceDenialPause
            }
        }
        guard case .grant(let index, let duration) = decision,
              let added = addGrants(for: purposes, keyBlob: keyBlob, provenance: provenance, requesterIndex: index, duration: min(duration, GrantPresentation.maximumDuration)) else {
            return false
        }
        await issueCertificate(for: purposes, keyBlob: keyBlob, requester: added.requester, expires: added.expires, provenance: provenance)
        return true
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

    /// The host as the window shows it. If the known_hosts lines that matched do not name the host literally (e.g.
    /// `*.example`), the window says which entry matched.
    static func displayHost(name: String, port: UInt32, matchingPatterns: [String]) -> String {
        let candidate = (port == 22 ? name : "[\(name)]:\(port)").lowercased()
        let display = port == 22 ? name : "\(name):\(port)"
        let indirect = matchingPatterns.filter { patterns in
            !patterns.lowercased().split(separator: ",").contains { $0.trimmingCharacters(in: .whitespaces) == candidate }
        }
        guard !indirect.isEmpty else { return display }
        return "\(display) (known_hosts entry \u{201C}\(Set(indirect).sorted().joined(separator: "; "))\u{201D})"
    }

    static func pauseKey(_ context: SSHAgent.ProtocolExtension.GrantRequestContext, chain: [SigningRequestProvenance.Process], requesterIndex: Int?) -> String {
        let requester = requesterIndex.map { chain[$0] } ?? chain[0]
        return "\(requester.pid)@\(requester.startTime?.timeIntervalSince1970 ?? -1) \(context.keyBlob.base64EncodedString()) \(context.purpose)"
    }

    /// The first secret except the grant CA, for requests that do not name a key.
    func firstSecret(except authority: Data?) async -> (AnySecret, AnySecretStore)? {
        await storeList.allSecretsWithStores.first { publicKeyWriter.data(secret: $0.0) != authority }
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
