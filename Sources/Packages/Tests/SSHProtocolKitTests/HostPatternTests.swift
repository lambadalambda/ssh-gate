import Foundation
import Testing
@testable import SSHProtocolKit

@Suite struct HostPatternTests {

    @Test(arguments: [
        ("a.corp.example", "*.corp.example", true),
        ("github.com", "*.corp.example", false),
        ("A.Corp.Example", "*.corp.example", true),
        ("host1.example", "host?.example", true),
        ("host10.example", "host?.example", false),
        ("bad.example", "*.example,!bad.example", false),
        ("good.example", "*.example,!bad.example", true),
        ("127.0.0.1", "[127.0.0.1]:2222", true),
        ("127.0.0.2", "[127.0.0.1]:2222", false),
        ("anything", "!*", false),
        ("second.example", "first.example, second.example", true),
    ])
    func matches(host: String, patterns: String, expected: Bool) {
        #expect(HostPattern.matches(host, patterns: patterns) == expected)
    }


    @Test(arguments: [
        ("git.example", UInt32(22), "git.example", true),
        ("git.example", UInt32(22), "*.example", true),
        ("git.example", UInt32(2222), "git.example", false),
        ("git.example", UInt32(2222), "[git.example]:2222", true),
        ("git.example", UInt32(22), "[git.example]:2222", false),
        ("127.0.0.1", UInt32(2241), "[127.0.0.1]:2241,other", true),
    ])
    func matchesHostAndPort(host: String, port: UInt32, patterns: String, expected: Bool) {
        #expect(HostPattern.matches(host: host, port: port, patterns: patterns) == expected)
    }

}
