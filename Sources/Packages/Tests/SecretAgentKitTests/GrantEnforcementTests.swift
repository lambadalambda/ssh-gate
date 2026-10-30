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
