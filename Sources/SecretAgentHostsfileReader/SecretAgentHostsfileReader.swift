import Foundation
import OSLog
import XPCWrappers
import SSHProtocolKit

final class SecretAgentHostsfileReader: NSObject, XPCProtocol {

    private let logger = Logger(subsystem: "com.maxgoedjen.secretive.SecretAgentHostsfileReader", category: "SecretAgentHostsfileReader")

    func process(_ data: Data) async throws -> KnownHosts {
        logger.log("Parsing hostsfile")
        let contents = try Data(contentsOf: URL(filePath: NSHomeDirectory().appending("/.ssh/known_hosts")))
        return KnownHostsParser.parse(contents)
    }

}
