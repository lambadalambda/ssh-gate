import Foundation
import Testing
import SecretKit
@testable import SecretAgentKit

@Suite struct GrantSetTests {

    let key = Data("key".utf8)
    let hostKey = Data("host".utf8)
    let now = Date(timeIntervalSince1970: 1_000_000)
    let agentChain = chain("ssh", "git", "bash", "claude", "zsh", "login", "iTerm2")

    var login: GrantPurpose { .login(username: "git", hostKey: hostKey) }

    func grantSet(requester index: Int = 3, purpose: GrantPurpose? = nil, expires: TimeInterval = 3600) -> GrantSet {
        var set = GrantSet()
        let requester = GrantRequester(process: agentChain[index])!
        set.add(Grant(publicKey: key, requester: requester, purpose: purpose ?? login, expires: now.addingTimeInterval(expires)))
        return set
    }

    @Test func matchesSameRequestFromDescendant() {
        #expect(grantSet().match(publicKey: key, chain: agentChain, purpose: login, now: now) != nil)
        // A later ssh from the same agent has a new leaf process.
        var later = agentChain
        later[0] = later[0].with(pid: 999, startTime: now)
        #expect(grantSet().match(publicKey: key, chain: later, purpose: login, now: now) != nil)
    }

    @Test func otherKeyDoesNotMatch() {
        #expect(grantSet().match(publicKey: Data("other".utf8), chain: agentChain, purpose: login, now: now) == nil)
    }

    @Test(arguments: [
        GrantPurpose.login(username: "root", hostKey: Data("host".utf8)),
        GrantPurpose.login(username: "git", hostKey: Data("other".utf8)),
        GrantPurpose.signature(namespace: "git"),
    ])
    func otherPurposeDoesNotMatch(purpose: GrantPurpose) {
        #expect(grantSet().match(publicKey: key, chain: agentChain, purpose: purpose, now: now) == nil)
    }

    @Test func signaturePurpose() {
        let set = grantSet(purpose: .signature(namespace: "git"))
        #expect(set.match(publicKey: key, chain: agentChain, purpose: .signature(namespace: "git"), now: now) != nil)
        #expect(set.match(publicKey: key, chain: agentChain, purpose: .signature(namespace: "file"), now: now) == nil)
    }

    @Test func requesterOutsideChainDoesNotMatch() {
        // Another agent in another terminal tab.
        let other = agentChain.map { $0.with(pid: $0.pid + 50) }
        #expect(grantSet().match(publicKey: key, chain: other, purpose: login, now: now) == nil)
    }

    @Test func reusedPIDDoesNotMatch() {
        for delta in [500, 0.000_001] {
            let reused = agentChain.map { $0.with(startTime: $0.startTime?.addingTimeInterval(delta)) }
            #expect(grantSet().match(publicKey: key, chain: reused, purpose: login, now: now) == nil)
        }
    }

    @Test func invalidRequesters() {
        let p = SigningRequestProvenance.Process(pid: 100, processName: "x", appName: nil, iconURL: nil, path: "/x", validSignature: true, parentPID: nil)
        #expect(GrantRequester(process: p) == nil)
        #expect(GrantRequester(process: p.with(pid: 1, startTime: now)) == nil)
        #expect(GrantRequester(process: p.with(pid: 0, startTime: now)) == nil)
    }

    @Test func matchesAmongSeveralGrants() {
        var set = grantSet(purpose: .signature(namespace: "git"))
        set.add(Grant(publicKey: key, requester: GrantRequester(process: agentChain[3])!, purpose: login, expires: now.addingTimeInterval(10)))
        #expect(set.match(publicKey: key, chain: agentChain, purpose: login, now: now)?.purpose == login)
    }

    @Test func expiry() {
        let set = grantSet(expires: 60)
        #expect(set.match(publicKey: key, chain: agentChain, purpose: login, now: now.addingTimeInterval(59)) != nil)
        #expect(set.match(publicKey: key, chain: agentChain, purpose: login, now: now.addingTimeInterval(60)) == nil)
    }

    @Test func removeExpired() {
        var set = grantSet(expires: 60)
        set.removeExpired(now: now.addingTimeInterval(30))
        #expect(set.grants.count == 1)
        set.removeExpired(now: now.addingTimeInterval(60))
        #expect(set.grants.isEmpty)
    }

}
