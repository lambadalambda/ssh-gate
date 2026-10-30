import Foundation
import Testing
@testable import SSHProtocolKit

@Suite struct KnownHostsParserTests {

    let p256 = CapturedFixtures.logins["ecdsa256"]!.hostKey
    let p384 = CapturedFixtures.logins["ecdsa384"]!.hostKey
    let ed = CapturedFixtures.logins["ed25519"]!.hostKey

    func line(_ hosts: String, _ key: Data, comment: String = "") -> String {
        let type = String(decoding: try! OpenSSHReader(data: key).readNextChunk(), as: UTF8.self)
        return "\(hosts) \(type) \(key.base64EncodedString())\(comment.isEmpty ? "" : " " + comment)"
    }

    @Test func keysByFullBlob() {
        let hosts = KnownHostsParser.parse(Data([line("a.example", p256), line("b.example", p384)].joined(separator: "\n").utf8))
        #expect(hosts[p256] == "a.example")
        #expect(hosts[p384] == "b.example")
    }

    @Test func mergesNamesAndAcceptsComments() {
        let contents = [line("a.example", ed, comment: "my server"), line("10.0.0.1", ed)].joined(separator: "\n")
        #expect(KnownHostsParser.parse(Data(contents.utf8))[ed] == "a.example, 10.0.0.1")
    }

    @Test func acceptsTabsAndBadLines() {
        let tabbed = line("a.example", ed).replacingOccurrences(of: " ", with: "\t")
        var contents = Data(tabbed.utf8)
        contents.append(contentsOf: [0x0a, 0xff, 0xfe, 0x0a])
        contents.append(Data(line("b.example", p256).utf8))
        let hosts = KnownHostsParser.parse(contents)
        #expect(hosts[ed] == "a.example")
        #expect(hosts[p256] == "b.example")
    }

    @Test func skipsMarkersHashedAndInvalidLines() {
        let contents = [
            "# comment",
            "",
            "@cert-authority *.example " + line("", p256).dropFirst(),
            "@revoked * " + line("", p384).dropFirst(),
            line("|1|c2FsdA==|aGFzaA==", ed),
            "broken line",
            "x.example ssh-ed25519 !!!notbase64",
            "y.example ssh-rsa " + ed.base64EncodedString(), // type does not match the blob
        ].joined(separator: "\n")
        #expect(KnownHostsParser.parse(Data(contents.utf8)).isEmpty)
    }

}
