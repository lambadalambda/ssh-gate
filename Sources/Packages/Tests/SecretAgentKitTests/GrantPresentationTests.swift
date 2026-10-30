import Foundation
import Testing
import SSHTestFixtures
@testable import SecretKit
@testable import SecretAgentKit

@Suite struct GrantPresentationTests {

    let secret = AnySecret(AgentTests.Constants.Secrets.ecdsa256Secret)
    let provenance = SigningRequestProvenance(chain: chain("ssh", "git", "bash", "claude", "zsh", "login", "iTerm2"))
    let hostKey = CapturedFixtures.logins["ed25519"]!.hostKey

    func presentation(_ purpose: GrantPurpose?, host: String? = nil, forwarded: Bool = false, defaultIndex: Int? = 3) -> GrantPresentation {
        GrantPresentation(GrantRequest(secret: secret, provenance: provenance, purpose: purpose, host: host, defaultRequesterIndex: defaultIndex, forwarded: forwarded))
    }

    @Test func purposeTexts() {
        #expect(presentation(.login(username: "git", hostKey: hostKey), host: "github.com").purpose == "Log in as git to github.com")
        #expect(presentation(.login(username: "git", hostKey: hostKey)).purpose == "Log in as git to a host that is not in known_hosts")
        #expect(presentation(.signature(namespace: "git")).purpose == "Sign a git commit or tag")
        #expect(presentation(.signature(namespace: "file")).purpose == "Sign data in the namespace \"file\"")
        #expect(presentation(nil).purpose == "Unverified request: the purpose cannot be checked")
        #expect(presentation(nil, forwarded: true).purpose == "Request through a forwarded agent connection")
    }

    @Test func hostKeyFingerprintMatchesOpenSSH() {
        // ssh-keygen -lf of the captured ed25519 host key.
        #expect(presentation(.login(username: "git", hostKey: hostKey)).hostKeyFingerprint == "SHA256:bbzE4hsjBSAab8QRvR+Vs8aolV4VBSghnNLEsp223RM")
        #expect(presentation(.signature(namespace: "git")).hostKeyFingerprint == nil)
    }

    @Test func titleDoesNotUseProcessNames() {
        let p = presentation(.signature(namespace: "git"))
        #expect(p.title == "Request to use the key \u{201C}\(secret.name)\u{201D}")
    }

    @Test func authenticationReason() {
        let p = presentation(.login(username: "git", hostKey: hostKey), host: "github.com")
        #expect(p.authenticationReason(duration: 2, requester: 3) == "allow claude (/bin/claude) to log in as git to github.com with the key \u{201C}\(secret.name)\u{201D} for 1 hour")
        #expect(p.authenticationReason(duration: 0, requester: 3) == "allow this request to log in as git to github.com with the key \u{201C}\(secret.name)\u{201D} once")
    }

    @Test func durationsOnlyWithVerifiedPurpose() {
        #expect(presentation(.signature(namespace: "git")).durations.map(\.label) == ["Only this request", "15 minutes", "1 hour", "4 hours", "8 hours"])
        #expect(presentation(nil).durations.map(\.label) == ["Only this request"])
        #expect(presentation(.signature(namespace: "git"), forwarded: true).durations.map(\.label) == ["Only this request"])
        #expect(presentation(.signature(namespace: "git"), defaultIndex: nil).defaultDuration == 0)
        #expect(presentation(.signature(namespace: "git")).defaultDuration == 2)
    }

    @Test func decisions() {
        let p = presentation(.signature(namespace: "git"))
        #expect(p.decision(duration: 0, requester: 3) == .once)
        #expect(p.decision(duration: 2, requester: 3) == .grant(requesterIndex: 3, duration: 3600))
        #expect(p.decision(duration: 4, requester: 2) == .grant(requesterIndex: 2, duration: 8 * 3600))
        #expect(p.decision(duration: 2, requester: nil) == .once)
        #expect(p.decision(duration: 99, requester: 3) == .once)
    }

    @Test func requesterRows() {
        let p = presentation(.signature(namespace: "git"))
        #expect(p.requesters.map(\.index) == [0, 1, 2, 3, 4, 5, 6])
        #expect(p.requesters[3].name == "claude")
        #expect(p.requesters[3].path == "/bin/claude")
        // Processes that cannot hold a grant are not selectable.
        let launchd = GrantPresentation(GrantRequest(secret: secret, provenance: SigningRequestProvenance(chain: chain("ssh", "launchd")), purpose: .signature(namespace: "git"), host: nil, defaultRequesterIndex: nil, forwarded: false))
        #expect(launchd.requesters.map(\.selectable) == [true, false])
    }

}

