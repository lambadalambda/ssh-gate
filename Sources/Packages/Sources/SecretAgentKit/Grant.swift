import Foundation
import SecretKit

/// What a grant allows a key to be used for.
public enum GrantPurpose: Hashable, Sendable {
    /// Log in as `username` to the host with this host key. The host key must come from a verified session-bind.
    case login(username: String, hostKey: Data)
    /// Sign SSHSIG data in this namespace, e.g. "git".
    case signature(namespace: String)
}

/// The process a grant belongs to. Requests from this process and all its descendants match.
public struct GrantRequester: Hashable, Sendable {

    public let pid: Int32
    public let startTime: Date
    public let path: String

    /// - Returns: `nil` if the start time is unknown, because the pid alone can be reused, and for the kernel and
    ///   launchd (pid 0 and 1), which are ancestors of every process.
    public init?(process: SigningRequestProvenance.Process) {
        guard let startTime = process.startTime, process.pid > 1 else { return nil }
        self.pid = process.pid
        self.startTime = startTime
        self.path = process.path
    }

    func isSame(as process: SigningRequestProvenance.Process) -> Bool {
        process.pid == pid && process.startTime == startTime
    }

}

/// Permission for one requester to use one key for one purpose until a point in time.
public struct Grant: Identifiable, Hashable, Sendable {

    public let id: UUID
    /// The public key blob of the secret.
    public let publicKey: Data
    public let requester: GrantRequester
    public let purpose: GrantPurpose
    /// Compare with the wall clock: a sleeping Mac must not extend a grant.
    public let expires: Date

    public init(id: UUID = UUID(), publicKey: Data, requester: GrantRequester, purpose: GrantPurpose, expires: Date) {
        self.id = id
        self.publicKey = publicKey
        self.requester = requester
        self.purpose = purpose
        self.expires = expires
    }

}

/// A set of grants. A value type, so callers decide about isolation.
public struct GrantSet: Sendable {

    public private(set) var grants: [Grant] = []

    public init() {}

    public mutating func add(_ grant: Grant) {
        grants.append(grant)
    }

    /// Returns a grant that allows the request, if there is one.
    /// - Parameters:
    ///   - publicKey: The public key blob of the secret that would sign.
    ///   - chain: The request's process chain, from the connecting process to the app.
    ///   - purpose: The verified purpose of the request.
    ///   - now: The current wall-clock time.
    public func match(publicKey: Data, chain: [SigningRequestProvenance.Process], purpose: GrantPurpose, now: Date) -> Grant? {
        grants.first { grant in
            grant.publicKey == publicKey
                && grant.purpose == purpose
                && now < grant.expires
                && chain.contains { grant.requester.isSame(as: $0) }
        }
    }

    public mutating func removeExpired(now: Date) {
        grants.removeAll { now >= $0.expires }
    }

}
