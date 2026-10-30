import Foundation

/// Host patterns as in known_hosts (`*` and `?` wildcards, `!` negation, `[host]:port`), like OpenSSH's
/// match_hostname. Case-insensitive.
public enum HostPattern {

    /// Whether `host` matches the comma-separated `patterns`, ignoring ports in `[host]:port` patterns (e.g. for
    /// certificate principals, which have no port). A matching negated pattern wins over all others.
    public static func matches(_ host: String, patterns: String) -> Bool {
        matches(candidate: host, patterns: patterns, ignorePorts: true)
    }

    /// Whether a connection to `host` on `port` matches the patterns, as ssh looks it up in known_hosts: `host` for
    /// port 22, `[host]:port` otherwise.
    public static func matches(host: String, port: UInt32, patterns: String) -> Bool {
        matches(candidate: port == 22 ? host : "[\(host)]:\(port)", patterns: patterns, ignorePorts: false)
    }

    static func matches(candidate: String, patterns: String, ignorePorts: Bool) -> Bool {
        let host = candidate.lowercased()
        var matched = false
        for rawPattern in patterns.split(separator: ",") {
            var pattern = Substring(rawPattern.lowercased().trimmingCharacters(in: .whitespaces))
            let negated = pattern.hasPrefix("!")
            if negated {
                pattern = pattern.dropFirst()
            }
            if ignorePorts, pattern.hasPrefix("["), let end = pattern.firstIndex(of: "]") {
                pattern = pattern[pattern.index(after: pattern.startIndex)..<end]
            }
            guard glob(Array(pattern), Array(host)) else { continue }
            if negated {
                return false
            }
            matched = true
        }
        return matched
    }

    static func glob(_ pattern: [Character], _ text: [Character]) -> Bool {
        guard let first = pattern.first else { return text.isEmpty }
        switch first {
        case "*":
            let rest = Array(pattern.dropFirst())
            return (0...text.count).contains { glob(rest, Array(text.dropFirst($0))) }
        case "?":
            return !text.isEmpty && glob(Array(pattern.dropFirst()), Array(text.dropFirst()))
        default:
            return text.first == first && glob(Array(pattern.dropFirst()), Array(text.dropFirst()))
        }
    }

}
