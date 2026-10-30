import Foundation

/// Host patterns as in known_hosts (`*` and `?` wildcards, `!` negation, `[host]:port`), like OpenSSH's
/// match_hostname. Case-insensitive.
public enum HostPattern {

    /// Whether `host` matches the comma-separated `patterns`. A matching negated pattern wins over all others.
    public static func matches(_ host: String, patterns: String) -> Bool {
        let host = host.lowercased()
        var matched = false
        for rawPattern in patterns.split(separator: ",") {
            var pattern = Substring(rawPattern.lowercased())
            let negated = pattern.hasPrefix("!")
            if negated {
                pattern = pattern.dropFirst()
            }
            if pattern.hasPrefix("["), let end = pattern.firstIndex(of: "]") {
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
