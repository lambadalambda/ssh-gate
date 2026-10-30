import Foundation
import SecretKit

/// Chooses which process in a request chain a grant should belong to.
public enum RequesterSelection {

    /// Shells, session helpers and tools that run on behalf of the actual requester.
    static let intermediaries: Set<String> = [
        "sh", "bash", "zsh", "fish", "dash", "ksh", "tcsh", "csh", "nu", "login", "sudo", "env", "nohup", "xargs", "make",
        "git", "ssh", "ssh-keygen", "scp", "sftp", "rsync",
    ]

    /// The index of the default requester in a chain that starts at the connecting process and ends at the app.
    ///
    /// Walks down from the app and returns the first process that is not an intermediary, such as a coding agent
    /// started in a terminal. If there is none, the request comes straight from the app's own session, so the app is
    /// the requester.
    /// - Returns: `nil` for an empty chain.
    public static func defaultIndex(in chain: [SigningRequestProvenance.Process]) -> Int? {
        guard let top = chain.indices.last else { return nil }
        for index in stride(from: top - 1, to: 0, by: -1) where !isIntermediary(chain[index]) {
            return index
        }
        return top
    }

    static func isIntermediary(_ process: SigningRequestProvenance.Process) -> Bool {
        var name = process.processName
        if name.hasPrefix("-") {
            name.removeFirst()
        }
        return intermediaries.contains(name)
    }

}
