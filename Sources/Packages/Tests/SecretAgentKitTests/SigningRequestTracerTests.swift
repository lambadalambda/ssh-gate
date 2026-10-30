import Foundation
import Testing
@testable import SecretAgentKit

@Suite struct SigningRequestTracerTests {

    @Test func startTimeIsStable() throws {
        let tracer = SigningRequestTracer()
        let first = try #require(tracer.process(from: getpid())?.startTime)
        let second = try #require(tracer.process(from: getpid())?.startTime)
        #expect(first == second)
        #expect(first <= Date())
        #expect(first > Date().addingTimeInterval(-24 * 60 * 60))
    }

    @Test func parentHasEarlierStartTime() throws {
        let tracer = SigningRequestTracer()
        let me = try #require(tracer.process(from: getpid()))
        let parentPID = try #require(me.parentPID)
        let parent = try #require(tracer.process(from: parentPID))
        #expect(SigningRequestTracer.isPlausibleParent(parent, of: me))
    }


    @Test func signatureStatusFromKernel() {
        // The test runner is signed; pid 999_999_999 does not exist.
        #expect(SigningRequestTracer().hasValidSignature(pid: getpid()))
        #expect(!SigningRequestTracer().hasValidSignature(pid: 999_999_999))
        #expect(SigningRequestTracer.csValid(status: 0x2202_0201))
        #expect(!SigningRequestTracer.csValid(status: 0x2202_0200))
    }

}
