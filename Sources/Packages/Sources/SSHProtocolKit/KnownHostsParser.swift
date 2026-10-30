import Foundation

/// Host names and certificate authorities from a known_hosts file.
public struct KnownHosts: Codable, Sendable, Equatable {
    /// Full host key blobs and the host names of their lines.
    public var names: [Data: String]
    /// CA key blobs of `@cert-authority` lines and their host patterns.
    public var authorities: [Data: String]

    public init(names: [Data: String], authorities: [Data: String]) {
        self.names = names
        self.authorities = authorities
    }
}

/// Reads a known_hosts file, for display only. Grants pin host keys, not names.
public enum KnownHostsParser {

    /// Hashed host names and `@revoked` lines are skipped, so a key never shows a name that the file does not state for it.
    public static func parse(_ contents: Data) -> KnownHosts {
        var names: [Data: [String]] = [:]
        var authorities: [Data: [String]] = [:]
        for rawLine in contents.split(separator: UInt8(ascii: "\n")) {
            // Decode each line on its own, so one invalid line does not hide the others.
            let line = String(decoding: rawLine, as: UTF8.self)
            var fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" || $0 == "\r" }).map(String.init)
            var marker: String?
            if fields.first?.hasPrefix("@") == true {
                marker = fields.removeFirst()
            }
            guard fields.count >= 3,
                  !fields[0].hasPrefix("#"), !fields[0].hasPrefix("|"),
                  let blob = Data(base64Encoded: fields[2]),
                  let type = try? OpenSSHReader(data: blob).readNextChunkAsString(),
                  type == fields[1] else {
                continue
            }
            let patterns = fields[0].split(separator: ",").map(String.init)
            switch marker {
            case nil:
                names[blob, default: []].append(contentsOf: patterns)
            case "@cert-authority":
                authorities[blob, default: []].append(contentsOf: patterns)
            default:
                continue
            }
        }
        return KnownHosts(names: names.mapValues(joinUnique), authorities: authorities.mapValues(joinUnique))
    }

    static func joinUnique(_ values: [String]) -> String {
        values.reduce(into: [String]()) { if !$0.contains($1) { $0.append($1) } }.joined(separator: ", ")
    }

}
