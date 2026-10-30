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

}
