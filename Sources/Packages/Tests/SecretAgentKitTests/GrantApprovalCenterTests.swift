import Foundation
import Testing
@testable import SecretKit
@testable import SecretAgentKit

@Suite @MainActor struct GrantApprovalCenterTests {

    let secret = AnySecret(AgentTests.Constants.Secrets.ecdsa256Secret)
    let provenance = SigningRequestProvenance(chain: chain("ssh", "git", "bash", "claude", "zsh", "login", "iTerm2"))

    func request(_ purpose: GrantPurpose?, provenance: SigningRequestProvenance? = nil) -> GrantRequest {
        GrantRequest(secret: secret, provenance: provenance ?? self.provenance, purpose: purpose, host: nil, defaultRequesterIndex: 3, forwarded: false)
    }

    /// Waits until the center has `count` pending items.
    func pending(_ center: GrantApprovalCenter, count: Int) async throws {
        for _ in 0..<200 where center.pending.count < count {
            try await Task.sleep(for: .milliseconds(5))
        }
        try #require(center.pending.count == count)
    }

    @Test func decisionResumesRequest() async throws {
        let center = GrantApprovalCenter()
        var shown = 0
        center.onPendingRequest = { shown += 1 }
        async let decision = center.decide(request(.signature(namespace: "git")))
        try await pending(center, count: 1)
        #expect(shown == 1)
        center.resolve(center.pending[0], with: .once)
        #expect(await decision == .once)
        #expect(center.pending.isEmpty)
    }

    @Test func identicalRequestsShareOneApproval() async throws {
        let center = GrantApprovalCenter()
        var leaf = provenance
        leaf.chain[0] = leaf.chain[0].with(pid: 999)
        async let first = center.decide(request(.signature(namespace: "git")))
        try await pending(center, count: 1)
        async let second = center.decide(request(.signature(namespace: "git"), provenance: leaf))
        try await Task.sleep(for: .milliseconds(20))
        #expect(center.pending.count == 1)
        center.resolve(center.pending[0], with: .grant(requesterIndex: 3, duration: 60))
        #expect(await first == .grant(requesterIndex: 3, duration: 60))
        #expect(await second == .grant(requesterIndex: 3, duration: 60))
    }

    @Test func differentRequestsQueue() async throws {
        let center = GrantApprovalCenter()
        async let git = center.decide(request(.signature(namespace: "git")))
        try await pending(center, count: 1)
        async let file = center.decide(request(.signature(namespace: "file")))
        try await pending(center, count: 2)
        // Requests without a purpose are never merged.
        async let unknown1 = center.decide(request(nil))
        try await pending(center, count: 3)
        async let unknown2 = center.decide(request(nil))
        try await pending(center, count: 4)
        for decision in [GrantDecision.once, .deny, .once, .deny] {
            center.resolve(center.pending[0], with: decision)
        }
        #expect(await git == .once)
        #expect(await file == .deny)
        #expect(await unknown1 == .once)
        #expect(await unknown2 == .deny)
    }

    @Test func timeoutDenies() async throws {
        let center = GrantApprovalCenter(timeout: .milliseconds(50))
        #expect(await center.decide(request(.signature(namespace: "git"))) == .deny)
        #expect(center.pending.isEmpty)
    }

    @Test func resolvingTwiceIsHarmless() async throws {
        let center = GrantApprovalCenter()
        async let decision = center.decide(request(.signature(namespace: "git")))
        try await pending(center, count: 1)
        let item = center.pending[0]
        center.resolve(item, with: .once)
        center.resolve(item, with: .grant(requesterIndex: 3, duration: 60))
        #expect(await decision == .once)
    }


    @Test func connectingProcessIsPartOfMergeKey() async throws {
        let center = GrantApprovalCenter()
        async let first = center.decide(request(.signature(namespace: "git")))
        try await pending(center, count: 1)
        var otherBinary = provenance
        otherBinary.chain[0] = SigningRequestProvenance.Process(pid: 999, processName: "ssh", appName: nil, iconURL: nil, path: "/tmp/ssh", validSignature: false, parentPID: nil, startTime: Date())
        async let second = center.decide(request(.signature(namespace: "git"), provenance: otherBinary))
        try await pending(center, count: 2)
        center.denyAll()
        #expect(await first == .deny)
        #expect(await second == .deny)
    }

    @Test func mergedRequestsDoNotGrantOtherLeafProcesses() async throws {
        let center = GrantApprovalCenter()
        var leaf = provenance
        leaf.chain[0] = leaf.chain[0].with(pid: 999)
        async let first = center.decide(request(.signature(namespace: "git")))
        try await pending(center, count: 1)
        async let second = center.decide(request(.signature(namespace: "git"), provenance: leaf))
        try await Task.sleep(for: .milliseconds(20))
        #expect(center.pending[0].requestCount == 2)
        center.resolve(center.pending[0], with: .grant(requesterIndex: 0, duration: 60))
        #expect(await first == .grant(requesterIndex: 0, duration: 60))
        #expect(await second == .once)
    }

    @Test func denyAllAnswersEverything() async throws {
        let center = GrantApprovalCenter()
        async let git = center.decide(request(.signature(namespace: "git")))
        try await pending(center, count: 1)
        async let file = center.decide(request(.signature(namespace: "file")))
        try await pending(center, count: 2)
        center.denyAll()
        #expect(await git == .deny)
        #expect(await file == .deny)
        #expect(center.pending.isEmpty)
    }


    @Test func requestsThroughDifferentShellsOfOneAgentMerge() async throws {
        let center = GrantApprovalCenter()
        var otherShell = provenance
        otherShell.chain[0] = otherShell.chain[0].with(pid: 900)
        otherShell.chain[1] = otherShell.chain[1].with(pid: 901)
        otherShell.chain[2] = otherShell.chain[2].with(pid: 902)
        async let first = center.decide(request(.signature(namespace: "git")))
        try await pending(center, count: 1)
        async let second = center.decide(request(.signature(namespace: "git"), provenance: otherShell))
        try await Task.sleep(for: .milliseconds(20))
        #expect(center.pending.count == 1)
        center.resolve(center.pending[0], with: .once)
        #expect(await first == .once)
        #expect(await second == .once)
    }

    @Test func noDefaultRequesterNeverMerges() async throws {
        let center = GrantApprovalCenter()
        let noDefault = GrantRequest(secret: secret, provenance: provenance, purpose: .signature(namespace: "git"), host: nil, defaultRequesterIndex: nil, forwarded: false)
        async let first = center.decide(noDefault)
        try await pending(center, count: 1)
        async let second = center.decide(noDefault)
        try await pending(center, count: 2)
        center.denyAll()
        _ = await (first, second)
    }


    @Test func mergedDecisionsPointToTheSameRequester() async throws {
        let center = GrantApprovalCenter()
        // One more shell below the agent: the agent is at index 4 here, at index 3 in `provenance`.
        var longer = provenance
        longer.chain.insert(longer.chain[2].with(pid: 950), at: 2)
        let longerRequest = GrantRequest(secret: secret, provenance: longer, purpose: .signature(namespace: "git"), host: nil, defaultRequesterIndex: 4, forwarded: false)
        async let first = center.decide(request(.signature(namespace: "git")))
        try await pending(center, count: 1)
        async let second = center.decide(longerRequest)
        try await Task.sleep(for: .milliseconds(20))
        #expect(center.pending.count == 1)
        center.resolve(center.pending[0], with: .grant(requesterIndex: 4, duration: 60))
        #expect(await first == .grant(requesterIndex: 4, duration: 60))
        #expect(await second == .grant(requesterIndex: 5, duration: 60))
    }

    @Test func mergedDecisionBelowRequesterIsOnce() async throws {
        let center = GrantApprovalCenter()
        var otherShell = provenance
        otherShell.chain[2] = otherShell.chain[2].with(pid: 902)
        async let first = center.decide(request(.signature(namespace: "git")))
        try await pending(center, count: 1)
        async let second = center.decide(request(.signature(namespace: "git"), provenance: otherShell))
        try await Task.sleep(for: .milliseconds(20))
        center.resolve(center.pending[0], with: .grant(requesterIndex: 2, duration: 60))
        #expect(await first == .grant(requesterIndex: 2, duration: 60))
        #expect(await second == .once)
    }

}
