import Foundation
import Testing
import CertificateKit
import SSHTestFixtures
@testable import SSHProtocolKit
@testable import SecretKit
@testable import SecretAgentKit

/// Returns scripted decisions and records the requests it sees.
final class StubApprover: GrantApprover, @unchecked Sendable {

    private let lock = NSLock()
    private var _requests: [GrantRequest] = []
    var decision: GrantDecision

    init(_ decision: GrantDecision) {
        self.decision = decision
    }

    var requests: [GrantRequest] {
        lock.withLock { _requests }
    }

    func decide(_ request: GrantRequest) async -> GrantDecision {
        lock.withLock {
            _requests.append(request)
            return decision
        }
    }

}

private typealias Constants = AgentTests.Constants

final class Clock: @unchecked Sendable {
    var now = Date(timeIntervalSince1970: 2_000_000_000)
}

@Suite @MainActor struct GrantEnforcementTests {

    let approver = StubApprover(.grant(requesterIndex: 3, duration: 3600))
    let clock = Clock()
    let provenance = SigningRequestProvenance(chain: chain("ssh", "git", "bash", "claude", "zsh", "login", "iTerm2"))
    let otherAgent = SigningRequestProvenance(chain: chain("ssh", "git", "bash", "claude", "zsh", "login", "iTerm2").map { $0.with(pid: $0.pid + 50) })

    var keyBlob: Data {
        guard case .signRequest(let context) = try! SSHAgentInputParser().parse(data: Constants.Requests.requestSignature) else { fatalError() }
        return context.keyBlob
    }

    func makeAgent() async -> Agent {
        let list = await AgentTests().storeList(with: [Constants.Secrets.ecdsa256Secret])
        let clock = clock
        return Agent(storeList: list, certificateStore: CertificateStore(), authenticationHandler: AuthenticationHandler(), grantApprover: approver, now: { clock.now })
    }

    func sshsig(_ namespace: String) -> Data {
        var data = Data("SSHSIG".utf8)
        data.append(Data(namespace.utf8).lengthAndData)
        data.append(Data().lengthAndData)
        data.append(Data("sha512".utf8).lengthAndData)
        data.append(Data(repeating: 1, count: 64).lengthAndData)
        return signRequest(key: keyBlob, data: data)
    }

    func bind(_ host: String, forwarding: Bool = false) throws -> (request: Data, context: SSHAgent.ProtocolExtension.OpenSSHExtension.SessionBindContext) {
        var message = try #require(CapturedFixtures.logins[host]).sessionBind
        if forwarding { message[message.count - 1] = 1 }
        guard case .protocolExtension(.openSSH(.sessionBind(let context))) = try SSHAgentInputParser().parse(data: message) else {
            throw TestFailure()
        }
        return (message, context)
    }

    func login(sessionID: Data, hostKey: Data?) -> Data {
        var auth = UserAuth()
        auth.sessionID = sessionID
        auth.algorithm = "ecdsa-sha2-nistp256"
        auth.key = keyBlob
        auth.hostKey = hostKey
        if hostKey == nil { auth.method = "publickey" }
        return auth.request
    }

    func send(_ agent: Agent, _ message: Data, from provenance: SigningRequestProvenance, on connection: AgentConnection = AgentConnection(), knownHosts: KnownHosts? = nil) async throws -> Bool {
        // A new connection per message unless a test passes one.
        let response = await agent.handle(request: try SSHAgentInputParser().parse(data: message), provenance: provenance, hosts: knownHosts, connection: connection)
        return response != Constants.Responses.requestFailure
    }

    struct TestFailure: Error {}

    // MARK: Signatures

    @Test func grantCoversLaterRequestsOfSameRequester() async throws {
        let agent = await makeAgent()
        #expect(try await send(agent, sshsig("git"), from: provenance))
        #expect(approver.requests.count == 1)
        #expect(approver.requests[0].purpose == .signature(namespace: "git"))
        #expect(approver.requests[0].defaultRequesterIndex == 3)
        var laterLeaf = provenance
        laterLeaf.chain[0] = laterLeaf.chain[0].with(pid: 999, startTime: clock.now)
        #expect(try await send(agent, sshsig("git"), from: laterLeaf))
        #expect(approver.requests.count == 1)
    }

    @Test func requesterWithoutStartTimeIsOnce() async throws {
        let agent = await makeAgent()
        var noStart = provenance
        noStart.chain[3] = SigningRequestProvenance.Process(pid: noStart.chain[3].pid, processName: "claude", appName: nil, iconURL: nil, path: "/bin/claude", validSignature: true, parentPID: nil)
        #expect(try await send(agent, sshsig("git"), from: noStart))
        #expect(try await send(agent, sshsig("git"), from: noStart))
        #expect(approver.requests.count == 2)
    }

    @Test func infiniteDurationIsOnce() async throws {
        let agent = await makeAgent()
        approver.decision = .grant(requesterIndex: 3, duration: .infinity)
        #expect(try await send(agent, sshsig("git"), from: provenance))
        #expect(try await send(agent, sshsig("git"), from: provenance))
        #expect(approver.requests.count == 2)
    }

    @Test func forwardedBindsAreLimited() async throws {
        let agent = await makeAgent()
        let connection = AgentConnection()
        #expect(try await send(agent, try bind("ed25519", forwarding: true).request, from: provenance, on: connection))
        for _ in 1..<16 {
            #expect(try await send(agent, try bind("ecdsa256").request, from: provenance, on: connection))
        }
        #expect(try await !send(agent, try bind("ecdsa256").request, from: provenance, on: connection))
        #expect(try await !send(agent, sshsig("git"), from: provenance, on: connection))
    }

    // MARK: Requests in advance

    typealias RequestContext = SSHAgent.ProtocolExtension.GrantRequestContext

    func advance(_ purpose: RequestContext.Purpose, seconds: UInt32 = 3600, reason: String = "deploy") -> Data {
        var body = Data([27])
        body.append(Data(RequestContext.name.utf8).lengthAndData)
        body.append(RequestContext(keyBlob: keyBlob, purpose: purpose, seconds: seconds, reason: reason).encoded)
        return body.lengthAndData
    }

    var viaTool: SigningRequestProvenance {
        var p = provenance
        p.chain[0] = SigningRequestProvenance.Process(pid: 990, processName: "ssh-grant", appName: nil, iconURL: nil, path: "/usr/local/bin/ssh-grant", validSignature: true, parentPID: p.chain[1].pid, startTime: clock.now)
        return p
    }

    @Test func signatureRequestedInAdvance() async throws {
        let agent = await makeAgent()
        #expect(try await send(agent, advance(.signature(namespace: "git"), reason: "sign release"), from: viaTool))
        let request = try #require(approver.requests.first)
        #expect(request.advance)
        #expect(request.reason == "sign release")
        #expect(request.purpose == .signature(namespace: "git"))
        #expect(request.defaultRequesterIndex == 3)
        #expect(try await send(agent, sshsig("git"), from: provenance))
        #expect(approver.requests.count == 1)
    }

    @Test func loginRequestedInAdvanceResolvesKnownHosts() async throws {
        let agent = await makeAgent()
        let ed = try bind("ed25519")
        let p256 = try bind("ecdsa256")
        let known = KnownHosts(names: [ed.context.hostKey: "[127.0.0.1]:2241", p256.context.hostKey: "[127.0.0.1]:2241", keyBlob: "other.example"], authorities: [:])
        #expect(try await send(agent, advance(.login(host: "127.0.0.1", port: 2241, user: "root")), from: viaTool, knownHosts: known))
        let request = try #require(approver.requests.first)
        let purposes = Set([request.purpose].compactMap { $0 } + request.additionalPurposes)
        #expect(purposes == [.login(username: "root", hostKey: ed.context.hostKey), .login(username: "root", hostKey: p256.context.hostKey)])
        #expect(request.host == "127.0.0.1:2241")
        // A wildcard known_hosts line is named in the window.
        let wildcard = KnownHosts(names: [ed.context.hostKey: "*.example"], authorities: [:])
        #expect(try await send(agent, advance(.login(host: "git.example", port: 22, user: "deploy")), from: viaTool, knownHosts: wildcard))
        #expect(approver.requests.last?.host == "git.example (known_hosts entry \u{201C}*.example\u{201D})")
        approver.decision = .grant(requesterIndex: 3, duration: 3600)
        // Both host keys are granted.
        for host in [ed, p256] {
            let connection = AgentConnection()
            #expect(try await send(agent, host.request, from: provenance, on: connection))
            #expect(try await send(agent, login(sessionID: host.context.sessionID, hostKey: host.context.hostKey), from: provenance, on: connection))
        }
        #expect(approver.requests.count == 2)
    }

    @Test func advanceRequestsOnlyFromTheRequestTool() async throws {
        let agent = await makeAgent()
        // A remote host behind an agent forwarded without session-bind looks like the local ssh process.
        #expect(try await !send(agent, advance(.signature(namespace: "git")), from: provenance))
        #expect(approver.requests.isEmpty)
    }

    @Test func denialPausesRepeatedAdvanceRequests() async throws {
        let agent = await makeAgent()
        approver.decision = .deny
        #expect(try await !send(agent, advance(.signature(namespace: "git")), from: viaTool))
        #expect(try await !send(agent, advance(.signature(namespace: "git")), from: viaTool))
        #expect(approver.requests.count == 1)
        // Another purpose still asks.
        #expect(try await !send(agent, advance(.signature(namespace: "file")), from: viaTool))
        #expect(approver.requests.count == 2)
        clock.now += 31
        #expect(try await !send(agent, advance(.signature(namespace: "git")), from: viaTool))
        #expect(approver.requests.count == 3)
    }

    @Test func advanceRequestsThatCannotBeGranted() async throws {
        let agent = await makeAgent()
        let known = KnownHosts(names: [:], authorities: [:])
        // Unknown host: refused without asking.
        #expect(try await !send(agent, advance(.login(host: "unknown.example", port: 22, user: "root")), from: viaTool, knownHosts: known))
        #expect(approver.requests.isEmpty)
        // Forwarded connection: refused without asking.
        let forwarded = AgentConnection()
        #expect(try await send(agent, try bind("ed25519", forwarding: true).request, from: provenance, on: forwarded))
        #expect(try await !send(agent, advance(.signature(namespace: "git")), from: viaTool, on: forwarded))
        #expect(approver.requests.isEmpty)
        // Deny and once give no grant.
        for decision in [GrantDecision.deny, .once] {
            approver.decision = decision
            #expect(try await !send(agent, advance(.signature(namespace: "git")), from: viaTool))
            clock.now += Agent.advanceDenialPause + 1
        }
        approver.decision = .grant(requesterIndex: 3, duration: 3600)
        #expect(try await send(agent, sshsig("git"), from: provenance))
        #expect(approver.requests.count == 3)
    }

    @Test func coveredAdvanceRequestNeedsNoWindow() async throws {
        let agent = await makeAgent()
        let ed = try bind("ed25519")
        let known = KnownHosts(names: [ed.context.hostKey: "git.example"], authorities: [:])
        #expect(try await send(agent, advance(.login(host: "git.example", port: 22, user: "root")), from: viaTool, knownHosts: known))
        #expect(try await send(agent, advance(.login(host: "git.example", port: 22, user: "root")), from: viaTool, knownHosts: known))
        #expect(approver.requests.count == 1)
        // Another user, or another agent, is not covered.
        #expect(try await send(agent, advance(.login(host: "git.example", port: 22, user: "deploy")), from: viaTool, knownHosts: known))
        var otherTool = otherAgent
        otherTool.chain[0] = viaTool.chain[0].with(pid: 991)
        #expect(try await send(agent, advance(.login(host: "git.example", port: 22, user: "root")), from: otherTool, knownHosts: known))
        #expect(approver.requests.count == 3)
    }

    @Test func advanceDurationIsCapped() async throws {
        let agent = await makeAgent()
        #expect(try await send(agent, advance(.signature(namespace: "git"), seconds: 100 * 3600), from: viaTool))
        #expect(approver.requests.first?.requestedDuration == TimeInterval(8 * 3600))
    }

    // MARK: Certificates

    func makeAgentWithCA() async -> (Agent, Data) {
        let list = await AgentTests().storeList(with: [Constants.Secrets.ecdsa256Secret, Constants.Secrets.ecdsa384Secret])
        let ca = OpenSSHPublicKeyWriter().data(secret: Constants.Secrets.ecdsa384Secret)
        let clock = clock
        let agent = Agent(storeList: list, certificateStore: CertificateStore(), authenticationHandler: AuthenticationHandler(), grantApprover: approver, now: { clock.now }, certificateAuthority: { ca })
        return (agent, ca)
    }

    /// The identities that the agent lists, as (blob, comment).
    func identities(_ agent: Agent) async throws -> [(Data, String)] {
        let response = await agent.handle(request: .requestIdentities, provenance: provenance, hosts: nil, connection: AgentConnection())
        let reader = OpenSSHReader(data: response)
        _ = try reader.readNextBytes(as: UInt32.self)
        _ = try reader.readNextBytes(as: UInt8.self)
        let count = try reader.readNextBytes(as: UInt32.self)
        return try (0..<count).map { _ in (try reader.readNextChunk(), try reader.readNextChunkAsString()) }
    }

    @Test func loginGrantGetsCertificate() async throws {
        let (agent, ca) = await makeAgentWithCA()
        let ed = try bind("ed25519")
        let known = KnownHosts(names: [ed.context.hostKey: "git.example"], authorities: [:])
        #expect(try await send(agent, advance(.login(host: "git.example", port: 22, user: "deploy")), from: viaTool, knownHosts: known))

        let certificates = try await identities(agent).filter { HostCertificate.isCertificate($0.0) }
        try #require(certificates.count == 1)
        let blob = certificates[0].0
        let fields = try HostCertificate.Fields(blob)
        #expect(fields.certType == "ecdsa-sha2-nistp256-cert-v01@openssh.com")
        #expect(fields.type == 1)
        #expect(fields.principals == Data("deploy".utf8).lengthAndData)
        #expect(fields.validBefore == UInt64(clock.now.timeIntervalSince1970) + 3600)
        #expect(fields.validAfter == UInt64(clock.now.timeIntervalSince1970) - 60)
        #expect(fields.signatureKey == ca)
        try HostKeySignatureVerifier.verify(hostKey: ca, signature: fields.signature, data: Data(blob.prefix(blob.count - 4 - fields.signature.count)))

        // ssh signs with the certificate: the grant covers it.
        let connection = AgentConnection()
        #expect(try await send(agent, ed.request, from: provenance, on: connection))
        var auth = UserAuth()
        auth.sessionID = ed.context.sessionID
        auth.user = "deploy"
        auth.algorithm = "ecdsa-sha2-nistp256-cert-v01@openssh.com"
        auth.key = blob
        auth.hostKey = ed.context.hostKey
        #expect(try await send(agent, signRequest(key: blob, data: auth.data), from: provenance, on: connection))
        #expect(approver.requests.count == 1)

        // Expired certificates are no longer listed.
        clock.now += 3600
        #expect(try await identities(agent).filter { HostCertificate.isCertificate($0.0) }.isEmpty)
    }

    func certificates(_ agent: Agent) async throws -> [Data] {
        try await identities(agent).map(\.0).filter { HostCertificate.isCertificate($0) }
    }

    @Test func caKeyIsNotUsableByClients() async throws {
        let (agent, ca) = await makeAgentWithCA()
        #expect(try await !identities(agent).contains { $0.0 == ca })
        approver.decision = .once
        var data = Data("SSHSIG".utf8)
        for chunk in [Data("git".utf8), Data(), Data("sha512".utf8), Data(repeating: 1, count: 64)] { data.append(chunk.lengthAndData) }
        #expect(try await !send(agent, signRequest(key: ca, data: data), from: provenance))
        #expect(try await !send(agent, signRequest(key: ca, data: Data("anything".utf8)), from: provenance))
        #expect(approver.requests.isEmpty)
    }

    @Test func certificateFromSignRequestPathAndRenewal() async throws {
        let (agent, _) = await makeAgentWithCA()
        let ed = try bind("ed25519")
        for _ in 0..<2 {
            let connection = AgentConnection()
            #expect(try await send(agent, ed.request, from: provenance, on: connection))
            #expect(try await send(agent, login(sessionID: ed.context.sessionID, hostKey: ed.context.hostKey), from: provenance, on: connection))
            clock.now += 3600 // the grant expires, the next login asks again and renews the certificate
        }
        clock.now -= 3600
        #expect(try await certificates(agent).count == 1)
        #expect(approver.requests.count == 2)

        // A renewal in advance while the certificate is still valid replaces it.
        let known = KnownHosts(names: [ed.context.hostKey: "git.example"], authorities: [:])
        for _ in 0..<2 {
            clock.now += 31
            #expect(try await send(agent, advance(.login(host: "git.example", port: 22, user: "root")), from: viaTool, knownHosts: known))
        }
        #expect(try await certificates(agent).count == 1)
    }

    @Test func noCertificateForUnsafePrincipals() async throws {
        let (agent, _) = await makeAgentWithCA()
        let ed = try bind("ed25519")
        let connection = AgentConnection()
        #expect(try await send(agent, ed.request, from: provenance, on: connection))
        var auth = UserAuth()
        auth.sessionID = ed.context.sessionID
        auth.user = "deploy,root"
        auth.algorithm = "ecdsa-sha2-nistp256"
        auth.key = keyBlob
        auth.hostKey = ed.context.hostKey
        #expect(try await send(agent, signRequest(key: keyBlob, data: auth.data), from: provenance, on: connection))
        #expect(try await certificates(agent).isEmpty)
    }

    @Test func noCertificateWithoutCAOrForSignatures() async throws {
        let (withCA, _) = await makeAgentWithCA()
        #expect(try await send(withCA, advance(.signature(namespace: "git")), from: viaTool))
        #expect(try await identities(withCA).filter { HostCertificate.isCertificate($0.0) }.isEmpty)

        let agent = await makeAgent()
        let ed = try bind("ed25519")
        let known = KnownHosts(names: [ed.context.hostKey: "git.example"], authorities: [:])
        #expect(try await send(agent, advance(.login(host: "git.example", port: 22, user: "deploy")), from: viaTool, knownHosts: known))
        #expect(try await identities(agent).filter { HostCertificate.isCertificate($0.0) }.isEmpty)
    }

    // MARK: Without approver

    @Test func withoutApproverBindThenSignWorks() async throws {
        let list = await AgentTests().storeList(with: [Constants.Secrets.ecdsa256Secret])
        let agent = Agent(storeList: list, certificateStore: CertificateStore(), authenticationHandler: AuthenticationHandler())
        let ed = try bind("ed25519")
        let p256 = try bind("ecdsa256")
        let connection = AgentConnection()
        #expect(try await send(agent, ed.request, from: provenance, on: connection))
        #expect(try await send(agent, login(sessionID: ed.context.sessionID, hostKey: ed.context.hostKey), from: provenance, on: connection))
        #expect(try await !send(agent, p256.request, from: provenance, on: connection))
        #expect(try await !send(agent, login(sessionID: ed.context.sessionID, hostKey: ed.context.hostKey), from: provenance, on: connection))
    }

    @Test func otherScopeAsksAgain() async throws {
        let agent = await makeAgent()
        #expect(try await send(agent, sshsig("git"), from: provenance))
        #expect(try await send(agent, sshsig("file"), from: provenance))
        #expect(try await send(agent, sshsig("git"), from: otherAgent))
        #expect(approver.requests.count == 3)
    }

    @Test func expiredGrantAsksAgain() async throws {
        let agent = await makeAgent()
        #expect(try await send(agent, sshsig("git"), from: provenance))
        clock.now += 3600
        #expect(try await send(agent, sshsig("git"), from: provenance))
        #expect(approver.requests.count == 2)
    }

    @Test func denyAndOnce() async throws {
        let agent = await makeAgent()
        approver.decision = .deny
        #expect(try await !send(agent, sshsig("git"), from: provenance))
        approver.decision = .once
        #expect(try await send(agent, sshsig("git"), from: provenance))
        #expect(try await send(agent, sshsig("git"), from: provenance))
        #expect(approver.requests.count == 3)
    }

    @Test func invalidRequesterIndexIsOnce() async throws {
        let agent = await makeAgent()
        approver.decision = .grant(requesterIndex: 99, duration: 3600)
        #expect(try await send(agent, sshsig("git"), from: provenance))
        // The user may choose the app on purpose; that creates a grant.
        approver.decision = .grant(requesterIndex: 6, duration: 3600)
        #expect(try await send(agent, sshsig("git"), from: provenance))
        #expect(try await send(agent, sshsig("git"), from: provenance))
        #expect(approver.requests.count == 2)
    }

    // MARK: Logins

    @Test func loginGrantIsPerHost() async throws {
        let agent = await makeAgent()
        let ed = try bind("ed25519")
        let connection = AgentConnection()
        #expect(try await send(agent, ed.request, from: provenance, on: connection))
        #expect(try await send(agent, login(sessionID: ed.context.sessionID, hostKey: ed.context.hostKey), from: provenance, on: connection))
        #expect(approver.requests.last?.purpose == .login(username: "root", hostKey: ed.context.hostKey))

        // A new connection to the same host needs no new approval.
        let again = AgentConnection()
        #expect(try await send(agent, ed.request, from: provenance, on: again))
        #expect(try await send(agent, login(sessionID: ed.context.sessionID, hostKey: nil), from: provenance, on: again))
        #expect(approver.requests.count == 1)

        // Another host does.
        let p256 = try bind("ecdsa256")
        let other = AgentConnection()
        #expect(try await send(agent, p256.request, from: provenance, on: other))
        #expect(try await send(agent, login(sessionID: p256.context.sessionID, hostKey: p256.context.hostKey), from: provenance, on: other))
        #expect(approver.requests.count == 2)
    }

    @Test func hostCertificateShowsPrincipalsOnlyForKnownCA() async throws {
        let agent = await makeAgent()
        let login = try #require(CapturedFixtures.certLogins["ecdsa256c"])
        guard case .protocolExtension(.openSSH(.sessionBind(let bind))) = try SSHAgentInputParser().parse(data: login.sessionBind),
              let authority = bind.certificate?.authority else {
            throw TestFailure()
        }
        let trusted = KnownHosts(names: [:], authorities: [authority: "[127.0.0.1]:2222"])
        for (knownHosts, host) in [(trusted, "127.0.0.1"), (KnownHosts(names: [:], authorities: [:]), nil)] {
            let connection = AgentConnection()
            #expect(try await send(agent, login.sessionBind, from: provenance, on: connection, knownHosts: knownHosts))
            approver.decision = .once
            #expect(try await send(agent, self.login(sessionID: bind.sessionID, hostKey: login.hostKey), from: provenance, on: connection, knownHosts: knownHosts))
            #expect(approver.requests.last?.purpose == .login(username: "root", hostKey: login.hostKey))
            #expect(approver.requests.last?.host == host)
        }
    }

    @Test func hostNameRules() throws {
        let login = try #require(CapturedFixtures.certLogins["ed25519c"])
        guard case .protocolExtension(.openSSH(.sessionBind(let bind))) = try SSHAgentInputParser().parse(data: login.sessionBind),
              let ca = bind.certificate?.authority else {
            throw TestFailure()
        }
        let now = Date()
        func name(_ authorities: [Data: String], names: [Data: String] = [:], at time: Date = now, purpose: GrantPurpose? = nil) -> String? {
            Agent.hostName(for: purpose ?? GrantPurpose.login(username: "root", hostKey: login.hostKey), bind: bind, knownHosts: KnownHosts(names: names, authorities: authorities), now: time)
        }
        #expect(name([ca: "*"], names: [login.hostKey: "pinned.example"]) == "pinned.example")
        #expect(name([ca: "*"]) == "127.0.0.1, test.example")
        #expect(name([ca: "*.example"]) == "test.example")
        #expect(name([ca: "*.corp"]) == nil)
        #expect(name([ca: "*"], at: Date(timeIntervalSince1970: 0)) == nil)
        #expect(name([:]) == nil)
        let other = GrantPurpose.login(username: "root", hostKey: try #require(CapturedFixtures.logins["ed25519"]).hostKey)
        #expect(name([ca: "*"], purpose: other) == nil)
    }

    @Test func unverifiedLoginsHaveNoPurpose() async throws {
        let agent = await makeAgent()
        let ed = try bind("ed25519")
        let p256 = try bind("ecdsa256")

        // No bind.
        #expect(try await send(agent, login(sessionID: ed.context.sessionID, hostKey: ed.context.hostKey), from: provenance))
        // Session ID of another session.
        let mismatch = AgentConnection()
        #expect(try await send(agent, ed.request, from: provenance, on: mismatch))
        #expect(try await send(agent, login(sessionID: p256.context.sessionID, hostKey: ed.context.hostKey), from: provenance, on: mismatch))
        // Hostbound host key that differs from the bind.
        let wrongHost = AgentConnection()
        #expect(try await send(agent, ed.request, from: provenance, on: wrongHost))
        #expect(try await send(agent, login(sessionID: ed.context.sessionID, hostKey: p256.context.hostKey), from: provenance, on: wrongHost))

        #expect(approver.requests.map(\.purpose) == [nil, nil, nil])
        // Without a purpose, an approval counts once only.
        #expect(try await send(agent, login(sessionID: ed.context.sessionID, hostKey: ed.context.hostKey), from: provenance))
        #expect(approver.requests.count == 4)
    }

    @Test func forwardedConnectionAsksEveryTime() async throws {
        let agent = await makeAgent()
        let forwarded = try bind("ed25519", forwarding: true)
        let hop = try bind("ecdsa256")
        let connection = AgentConnection()
        #expect(try await send(agent, forwarded.request, from: provenance, on: connection))
        #expect(try await send(agent, hop.request, from: provenance, on: connection))
        #expect(try await send(agent, login(sessionID: hop.context.sessionID, hostKey: hop.context.hostKey), from: provenance, on: connection))
        #expect(try await send(agent, sshsig("git"), from: provenance, on: connection))
        #expect(approver.requests.map(\.purpose) == [nil, nil])
        #expect(approver.requests.allSatisfy { $0.forwarded })
    }

    @Test func secondBindPoisonsConnection() async throws {
        let agent = await makeAgent()
        let ed = try bind("ed25519")
        let p256 = try bind("ecdsa256")
        let connection = AgentConnection()
        #expect(try await send(agent, ed.request, from: provenance, on: connection))
        #expect(try await send(agent, ed.request, from: provenance, on: connection)) // the same bind again is fine
        #expect(try await !send(agent, p256.request, from: provenance, on: connection))
        #expect(try await !send(agent, sshsig("git"), from: provenance, on: connection))
        #expect(try await !send(agent, ed.request, from: provenance, on: connection))
        #expect(approver.requests.isEmpty)
    }

}
