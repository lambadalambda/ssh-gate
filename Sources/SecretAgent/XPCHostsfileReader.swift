import Foundation
import OSLog
import XPCWrappers
import SSHProtocolKit
import OSLog

public final class XPCHostsfileReader {

    private let logger = Logger(subsystem: "com.maxgoedjen.secretive.secretagent", category: "XPCHostsfileReader")
    private let session: XPCTypedSession<KnownHosts, HostsfileReaderError>

    public init() async throws {
        logger.debug("Creating XPCHostsfileReader")
        session = try await XPCTypedSession(serviceName: XPCServiceName.named("SecretAgentHostsfileReader"), warmup: true)
        logger.debug("XPCHostsfileReader is warmed up.")
    }

    public func read() async throws -> KnownHosts {
        logger.debug("Reading hosts file")
        defer { logger.debug("Read hosts file") }
        return try await session.send(Data())
    }

    deinit {
        session.complete()
    }

}

extension XPCHostsfileReader {

    public enum HostsfileReaderError: Error, Codable {
        case fileDoesNotExist
        case parseError
    }

}
