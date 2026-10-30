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
    ])
    func matches(host: String, patterns: String, expected: Bool) {
        #expect(HostPattern.matches(host, patterns: patterns) == expected)
    }

}
