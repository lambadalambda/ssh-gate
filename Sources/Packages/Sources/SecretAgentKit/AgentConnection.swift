import Foundation
import Synchronization
import SSHProtocolKit

/// The state of one client connection to the agent socket.
///
/// ssh binds a connection to one session with session-bind@openssh.com. A second, different bind on a normal
/// connection poisons it. A connection whose first bind is a forwarding bind belongs to a forwarded agent; it may bind
/// further hops, but its requests never get a purpose, so they need a one-time approval each.
public final class AgentConnection: Sendable {

    public typealias SessionBind = SSHAgent.ProtocolExtension.OpenSSHExtension.SessionBindContext
    typealias DecodedPayload = SSHAgent.Request.SignatureRequestContext.SignaturePayload.DecodedPayload

    struct State: Sendable {
        /// The first bind. On a normal connection, the only one.
        var bind: SessionBind?
        var bindCount = 0
        var forwarded = false
        var poisoned: String?
    }

    /// OpenSSH's AGENT_MAX_SESSION_IDS.
    static let maxBinds = 16

    struct Poisoned: Error {
        let reason: String
    }

    private let state = Mutex(State())

    public init() {}

    var snapshot: State {
        state.withLock { $0 }
    }

    func bind(_ bind: SessionBind) throws {
        try state.withLock { state in
            if let reason = state.poisoned {
                throw Poisoned(reason: reason)
            }
            guard let first = state.bind else {
                state.bind = bind
                state.bindCount = 1
                state.forwarded = bind.forwarding
                return
            }
            if state.forwarded, state.bindCount < Self.maxBinds {
                state.bindCount += 1
                return
            }
            if !state.forwarded, !bind.forwarding, bind.sessionID == first.sessionID, bind.hostKey == first.hostKey {
                return
            }
            let reason = state.forwarded ? "too many session-binds" : "more than one session-bind"
            state.poisoned = reason
            throw Poisoned(reason: reason)
        }
    }

    /// The verified purpose of a sign request on this connection, if there is one.
    static func purpose(of payload: DecodedPayload?, in state: State) -> GrantPurpose? {
        guard !state.forwarded, state.poisoned == nil else { return nil }
        switch payload {
        case .sshSig(let signature):
            return .signature(namespace: signature.namespace)
        case .sshConnection(let login):
            guard let bind = state.bind,
                  login.sessionID == bind.sessionID,
                  login.hostKey == nil || login.hostKey == bind.hostKey else {
                return nil
            }
            return .login(username: login.username, hostKey: bind.hostKey)
        case nil:
            return nil
        }
    }

}
