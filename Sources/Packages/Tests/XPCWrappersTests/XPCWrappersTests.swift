import Foundation
import Testing
@testable import XPCWrappers

@Suite struct XPCServiceNameTests {

    @Test func derivesFromMainBundle() {
        #expect(XPCServiceName.named("SecretAgentInputParser", mainBundleID: "com.maxgoedjen.Secretive.SecretAgent") == "com.maxgoedjen.Secretive.SecretAgentInputParser")
        #expect(XPCServiceName.named("SecretiveUpdater", mainBundleID: "com.example.sshgate.Host") == "com.example.sshgate.SecretiveUpdater")
    }

    @Test func fallsBackToUpstreamBase() {
        #expect(XPCServiceName.named("SecretiveUpdater", mainBundleID: nil) == "com.maxgoedjen.Secretive.SecretiveUpdater")
        #expect(XPCServiceName.named("SecretiveUpdater", mainBundleID: "nodots") == "com.maxgoedjen.Secretive.SecretiveUpdater")
    }

}

@Suite struct XPCTypedSessionTests {

    @Test(.timeLimit(.minutes(1))) func missingServiceFailsInsteadOfHanging() async throws {
        let session = try await XPCTypedSession<Data, Never>(serviceName: "com.example.does-not-exist", warmup: true)
        await #expect(throws: (any Error).self) {
            _ = try await session.send()
        }
    }

}

@Suite struct XPCCodeSigningTests {

    @Test func requirementPinsOwnTeam() {
        #expect(XPCCodeSigning.requirement(teamID: "ABCDE12345", debug: false) == "anchor apple generic and certificate leaf[subject.OU] = \"ABCDE12345\"")
        #expect(XPCCodeSigning.requirement(teamID: "ABCDE12345", debug: true) == "anchor apple generic and certificate leaf[subject.OU] = \"ABCDE12345\"")
    }

    @Test func unsignedBuilds() {
        #expect(XPCCodeSigning.requirement(teamID: nil, debug: true) == nil)
        #expect(XPCCodeSigning.requirement(teamID: nil, debug: false) == "never")
    }

    @Test func malformedTeamIDFailsClosed() {
        for team in ["", "SZ2F3U9QJ", "ABCDE12345\" or true", "sz2f3u9qj3"] {
            #expect(XPCCodeSigning.requirement(teamID: team, debug: true) == "never", "\(team)")
        }
    }

    @Test func requirementsCompile() throws {
        for requirement in [XPCCodeSigning.requirement(teamID: "ABCDE12345", debug: false)!, "never"] {
            var compiled: SecRequirement?
            let status = unsafe SecRequirementCreateWithString(requirement as CFString, [], &compiled)
            #expect(status == errSecSuccess, "\(requirement)")
        }
    }

}
