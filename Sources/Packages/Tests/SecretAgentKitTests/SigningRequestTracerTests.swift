import Foundation
import Testing
@testable import SecretAgentKit

@Suite struct SigningRequestTracerTests {

    @Test func startTimeIsStable() throws {
        let tracer = SigningRequestTracer()
        let first = try #require(tracer.process(from: getpid()).startTime)
        let second = try #require(tracer.process(from: getpid()).startTime)
        #expect(first == second)
        #expect(first <= Date())
        #expect(first > Date().addingTimeInterval(-24 * 60 * 60))
    }

    @Test func parentHasEarlierStartTime() throws {
        let tracer = SigningRequestTracer()
        let me = tracer.process(from: getpid())
        let parent = tracer.process(from: try #require(me.parentPID))
        #expect(try #require(parent.startTime) <= (try #require(me.startTime)))
    }

}
