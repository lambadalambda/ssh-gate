import Foundation

/// Reads host names from a known_hosts file, for display only. Grants pin host keys, not names.
public enum KnownHostsParser {

    /// Maps full host key blobs to the host names of their lines.
    ///
    /// Marker lines (`@cert-authority`, `@revoked`) and hashed host names are skipped, so a key never shows a
    /// name that the file does not state for it.
    public static func parse(_ contents: Data) -> [Data: String] {
        var names: [Data: [String]] = [:]
        for rawLine in contents.split(separator: UInt8(ascii: "\n")) {
            // Decode each line on its own, so one invalid line does not hide the others.
            let line = String(decoding: rawLine, as: UTF8.self)
            let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" || $0 == "\r" }).map(String.init)
            guard fields.count >= 3,
                  !fields[0].hasPrefix("@"), !fields[0].hasPrefix("#"), !fields[0].hasPrefix("|"),
                  let blob = Data(base64Encoded: fields[2]),
                  let type = try? OpenSSHReader(data: blob).readNextChunkAsString(),
                  type == fields[1] else {
                continue
            }
            names[blob, default: []].append(contentsOf: fields[0].split(separator: ",").map(String.init))
        }
        return names.mapValues { $0.reduce(into: [String]()) { if !$0.contains($1) { $0.append($1) } }.joined(separator: ", ") }
    }

}
