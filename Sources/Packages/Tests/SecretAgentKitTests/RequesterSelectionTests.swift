import Foundation
import Testing
import SecretKit
@testable import SecretAgentKit

/// Builds a chain from the process that connected (first) up to the app (last).
func chain(_ names: String...) -> [SigningRequestProvenance.Process] {
    names.enumerated().map { index, name in
        SigningRequestProvenance.Process(pid: Int32(100 + index), processName: name, appName: nil, iconURL: nil, path: "/bin/\(name)", validSignature: true, parentPID: Int32(101 + index), startTime: Date(timeIntervalSince1970: TimeInterval(index)))
    }
}

@Suite struct RequesterSelectionTests {

    @Test func agentBelowTerminal() {
        let c = chain("ssh", "git", "bash", "claude", "zsh", "login", "iTerm2")
        #expect(RequesterSelection.defaultIndex(in: c) == 3)
    }

    @Test func plainTerminalSelectsApp() {
        #expect(RequesterSelection.defaultIndex(in: chain("ssh", "zsh", "login", "Terminal")) == 3)
        #expect(RequesterSelection.defaultIndex(in: chain("ssh", "git", "zsh", "login", "Terminal")) == 4)
        #expect(RequesterSelection.defaultIndex(in: chain("ssh-keygen", "git", "-zsh", "login", "Terminal")) == 4)
    }

    @Test func agentStartedByTool() {
        let c = chain("ssh", "git", "sh", "codex", "fish", "Ghostty")
        #expect(RequesterSelection.defaultIndex(in: c) == 3)
    }

    @Test func shortChains() {
        #expect(RequesterSelection.defaultIndex(in: chain("ssh")) == 0)
        #expect(RequesterSelection.defaultIndex(in: chain("ssh", "Terminal")) == 1)
        #expect(RequesterSelection.defaultIndex(in: []) == nil)
    }

}
