import Foundation
import SecretKit

/// Chooses which process in a request chain a grant should belong to.
public enum RequesterSelection {

    static let shells: Set<String> = ["sh", "bash", "zsh", "fish", "dash", "ksh", "tcsh", "csh", "nu"]

    /// Shells, session helpers, terminal multiplexers and tools that run on behalf of the actual requester.
    static let intermediaries: Set<String> = shells.union([
        "login", "sudo", "env", "nohup", "xargs", "make", "tmux", "screen",
        "timeout", "nice", "time", "stdbuf", "caffeinate",
        "git", "ssh", "ssh-keygen", "scp", "sftp", "rsync", "ssh-grant",
    ])

    /// The index of the default requester in a chain that starts at the connecting process and ends at the top.
    ///
    /// 1. Walking up from the connecting process, the first process that is not an intermediary: the narrowest real
    ///    requester, such as a coding agent started in a terminal, or a tool that connects to the agent itself.
    /// 2. Else the outermost shell, which stands for one terminal tab or pane.
    /// 3. Else `nil`: there is no safe default, and the user must choose.
    ///
    /// GUI apps and pid 1 are never the default, because a grant to them would cover every process they start.
    public static func defaultIndex(in chain: [SigningRequestProvenance.Process]) -> Int? {
        let candidates = chain.indices.filter { !chain[$0].isApp && chain[$0].pid > 1 }
        return candidates.first { !isIntermediary(chain[$0]) }
            ?? candidates.last { shells.contains(name(of: chain[$0])) }
    }

    static func isIntermediary(_ process: SigningRequestProvenance.Process) -> Bool {
        intermediaries.contains(name(of: process))
    }

    /// The process name without the leading "-" of a login shell.
    static func name(of process: SigningRequestProvenance.Process) -> String {
        process.processName.hasPrefix("-") ? String(process.processName.dropFirst()) : process.processName
    }

}
