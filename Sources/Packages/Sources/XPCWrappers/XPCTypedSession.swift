import Foundation

public struct XPCTypedSession<ResponseType: Codable & Sendable, ErrorType: Error & Codable>: ~Copyable {

    private let connection: NSXPCConnection

    public init(serviceName: String, warmup: Bool = false) async throws {
        let connection = NSXPCConnection(serviceName: serviceName)
        connection.remoteObjectInterface = NSXPCInterface(with: (any _XPCProtocol).self)
        XPCCodeSigning.apply(to: connection)
        connection.resume()
        self.connection = connection
        if warmup {
            _ = try? await send()
        }
    }

    public func send(_ message: some Encodable = Data()) async throws -> ResponseType {
        let encoded = try JSONEncoder().encode(message)
        return try await withCheckedThrowingContinuation { continuation in
            // NSXPC calls exactly one of the error handler and the reply block, so a missing or crashed service
            // fails the request instead of leaving it waiting forever.
            let proxy = connection.remoteObjectProxyWithErrorHandler { error in
                continuation.resume(throwing: error)
            }
            guard let proxy = proxy as? _XPCProtocol else {
                continuation.resume(throwing: NoDataError())
                return
            }
            proxy.process(encoded) { data, error in
                do {
                    if let error {
                        throw error
                    }
                    guard let data else {
                        throw NoDataError()
                    }
                    let decoded = try JSONDecoder().decode(ResponseType.self, from: data)
                    continuation.resume(returning: decoded)
                } catch {
                    if let typed = (error as NSError).underlying(as: ErrorType.self) {
                        continuation.resume(throwing: typed)
                    } else {
                        continuation.resume(throwing: error)
                    }
                }
            }
        }
    }


    public func complete() {
        connection.invalidate()
    }

    public struct NoDataError: Error {}

}

