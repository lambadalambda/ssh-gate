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
