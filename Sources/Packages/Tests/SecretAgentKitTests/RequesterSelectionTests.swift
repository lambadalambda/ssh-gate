import Foundation
import Testing
import SecretKit
@testable import SecretAgentKit

let appNames: Set<String> = ["iTerm2", "Terminal", "Ghostty", "Code"]

/// Builds a chain from the process that connected (first) up to the top (last). Names in `appNames` are GUI apps;
/// "launchd" gets pid 1.
func chain(_ names: String...) -> [SigningRequestProvenance.Process] {
    names.enumerated().map { index, name in
        let isApp = appNames.contains(name)
        let pid: Int32 = name == "launchd" ? 1 : Int32(100 + index)
        return SigningRequestProvenance.Process(pid: pid, processName: name, appName: isApp ? name : nil, iconURL: nil, path: "/bin/\(name)", validSignature: true, parentPID: Int32(101 + index), startTime: Date(timeIntervalSince1970: TimeInterval(1000 - index)), isApp: isApp)
    }
}

extension SigningRequestProvenance {
    init(chain: [Process]) {
        self.init(root: chain[0])
        self.chain = chain
    }
}

extension SigningRequestProvenance.Process {
    func with(pid: Int32? = nil, startTime: Date? = nil) -> Self {
        .init(pid: pid ?? self.pid, processName: processName, appName: appName, iconURL: iconURL, path: path, validSignature: validSignature, parentPID: parentPID, startTime: startTime ?? self.startTime, isApp: isApp)
    }
}

@Suite struct RequesterSelectionTests {

    @Test func agentBelowTerminal() {
        let c = chain("ssh", "git", "bash", "claude", "zsh", "login", "iTerm2")
        #expect(RequesterSelection.defaultIndex(in: c) == 3)
    }

    @Test func plainTerminalSelectsTabShell() {
        #expect(RequesterSelection.defaultIndex(in: chain("ssh", "zsh", "login", "Terminal")) == 1)
        #expect(RequesterSelection.defaultIndex(in: chain("ssh", "git", "zsh", "login", "Terminal")) == 2)
        #expect(RequesterSelection.defaultIndex(in: chain("ssh-keygen", "git", "-zsh", "login", "Terminal")) == 2)
    }

    @Test func neverSelectsLaunchdOrNonAppTop() {
        #expect(RequesterSelection.defaultIndex(in: chain("ssh", "git", "launchd")) == nil)
        #expect(RequesterSelection.defaultIndex(in: chain("ssh", "cron", "launchd")) == 1)
        // tmux: the pane's shell, not the tmux server with all panes.
        #expect(RequesterSelection.defaultIndex(in: chain("ssh", "zsh", "tmux", "launchd")) == 1)
        // A truncated chain whose top is not an app.
        #expect(RequesterSelection.defaultIndex(in: chain("ssh", "git", "zsh")) == 2)
    }

    @Test func wrappersAreIntermediaries() {
        let c = chain("ssh-keygen", "timeout", "zsh", "2.1.280", "fish", "tmux", "launchd")
        #expect(RequesterSelection.defaultIndex(in: c) == 3)
        #expect(RequesterSelection.defaultIndex(in: chain("ssh", "nice", "stdbuf", "time", "caffeinate", "claude", "zsh", "login", "Terminal")) == 5)
    }

    @Test func narrowestProcessWins() {
        // In an editor's terminal, the pty host would cover all terminals of the editor.
        let c = chain("ssh", "git", "bash", "claude", "zsh", "Code Helper", "Code")
        #expect(RequesterSelection.defaultIndex(in: c) == 3)
    }

    @Test func appWithoutNameIsStillApp() {
        let c = chain("ssh", "zsh", "login", "Terminal").map {
            SigningRequestProvenance.Process(pid: $0.pid, processName: $0.processName, appName: nil, iconURL: nil, path: $0.path, validSignature: true, parentPID: $0.parentPID, startTime: $0.startTime, isApp: $0.isApp)
        }
        #expect(RequesterSelection.defaultIndex(in: c) == 1)
    }

    @Test func directClientIsRequester() {
        #expect(RequesterSelection.defaultIndex(in: chain("mytool", "zsh", "login", "Terminal")) == 0)
    }

    @Test func agentStartedByTool() {
        let c = chain("ssh", "git", "sh", "codex", "fish", "Ghostty")
        #expect(RequesterSelection.defaultIndex(in: c) == 3)
    }

    @Test func shortChains() {
        #expect(RequesterSelection.defaultIndex(in: chain("ssh")) == nil)
        #expect(RequesterSelection.defaultIndex(in: chain("ssh", "Terminal")) == nil)
        #expect(RequesterSelection.defaultIndex(in: []) == nil)
    }

}
