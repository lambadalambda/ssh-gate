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
