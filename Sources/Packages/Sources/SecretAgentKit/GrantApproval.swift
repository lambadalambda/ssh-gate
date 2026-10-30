import Foundation
import SecretKit

/// A request for permission that no grant covers.
public struct GrantRequest: Sendable {
    public let secret: AnySecret
    public let provenance: SigningRequestProvenance
    /// The verified purpose, or `nil` if the request cannot be verified (e.g. a login without session-bind). Without
    /// a purpose, only a one-time approval is possible.
    public let purpose: GrantPurpose?
    /// Host names for a login purpose, from known_hosts. For display only.
    public let host: String?
    /// The index in `provenance.chain` that a grant should belong to by default, see ``RequesterSelection``.
    public let defaultRequesterIndex: Int?
    /// The request comes through a forwarded agent connection. Only one-time approvals are possible.
    public let forwarded: Bool
    /// The request was made in advance (request-grant@heldscal.la), not by a signature request. Only grants make sense.
    public var advance = false
    /// The requester's own explanation. Not verified.
    public var reason: String? = nil
    /// Further purposes that the same decision covers, e.g. other host keys of the same host.
    public var additionalPurposes: [GrantPurpose] = []
    /// The duration the requester asked for, capped at the longest duration the window offers.
    public var requestedDuration: TimeInterval? = nil
}

public enum GrantDecision: Sendable, Equatable {
    case deny
    /// Allow this request only.
    case once
    /// Allow this and later requests with the same purpose from the process at `requesterIndex` in the chain, and from
    /// its descendants, for `duration` seconds.
    case grant(requesterIndex: Int, duration: TimeInterval)
}

/// Asks the user about requests that no grant covers.
public protocol GrantApprover: Sendable {
    func decide(_ request: GrantRequest) async -> GrantDecision
}
