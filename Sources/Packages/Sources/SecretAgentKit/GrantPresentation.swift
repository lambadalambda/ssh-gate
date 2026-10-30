import Foundation
import CryptoKit
import SecretKit

/// The content of the approval window for one ``GrantRequest``. Kept free of UI code so it can be tested.
public struct GrantPresentation: Sendable {

    public struct Duration: Sendable, Equatable {
        public let label: String
        /// `nil` for "only this request".
        public let seconds: TimeInterval?
    }

    public struct Requester: Sendable, Identifiable {
        public var id: Int { index }
        public let index: Int
        public let name: String
        public let path: String
        public let pid: Int32
        public let validSignature: Bool
        public let isApp: Bool
        /// Whether a grant can belong to this process (it has a start time and is not launchd).
        public let selectable: Bool
    }

    public let request: GrantRequest
    public let title: String
    /// The requester's reason, for display as its claim.
    public let reason: String?
    public let purpose: String
    /// Fingerprints of all host keys that a login grant would cover.
    public let hostKeyFingerprints: [String]
    public let durations: [Duration]
    /// Index into `durations`.
    public let defaultDuration: Int
    /// The process chain, from the process that connected to the app.
    public let requesters: [Requester]

    /// The longest duration the window offers.
    public static var maximumDuration: TimeInterval { allDurations.compactMap(\.seconds).max()! }

    static let allDurations: [Duration] = [
        .init(label: "Only this request", seconds: nil),
        .init(label: "15 minutes", seconds: 15 * 60),
        .init(label: "1 hour", seconds: 60 * 60),
        .init(label: "4 hours", seconds: 4 * 60 * 60),
        .init(label: "8 hours", seconds: 8 * 60 * 60),
    ]

    public init(_ request: GrantRequest) {
        self.request = request
        let chain = request.provenance.chain
        // Process names are chosen by the processes themselves, so the title does not show them.
        title = "Request to use the key \u{201C}\(request.secret.name)\u{201D}"

        switch (request.forwarded, request.purpose) {
        case (true, _):
            purpose = "Request through a forwarded agent connection"
        case (false, .login(let username, _)):
            purpose = "Log in as \(username) to \(request.host ?? "a host that is not in known_hosts")"
        case (false, .signature("git")):
            purpose = "Sign a git commit or tag"
        case (false, .signature(let namespace)):
            purpose = "Sign data in the namespace \"\(namespace)\""
        case (false, nil):
            purpose = "Unverified request: the purpose cannot be checked"
        }

        hostKeyFingerprints = ([request.purpose].compactMap { $0 } + request.additionalPurposes).compactMap { purpose in
            guard case .login(_, let hostKey) = purpose else { return nil }
            return "SHA256:" + Data(SHA256.hash(data: hostKey)).base64EncodedString().replacingOccurrences(of: "=", with: "")
        }
        reason = request.reason.flatMap { $0.isEmpty ? nil : $0 }

        let canGrant = request.purpose != nil && !request.forwarded
        if request.advance {
            durations = Array(Self.allDurations.dropFirst())
            let requested = request.requestedDuration ?? 3600
            defaultDuration = durations.lastIndex { ($0.seconds ?? 0) <= requested } ?? 0
        } else {
            durations = canGrant ? Self.allDurations : [Self.allDurations[0]]
            defaultDuration = canGrant && request.defaultRequesterIndex != nil ? 2 : 0
        }
        requesters = chain.enumerated().map { index, process in
            Requester(
                index: index,
                name: process.displayName,
                path: process.path,
                pid: process.pid,
                validSignature: process.validSignature,
                isApp: process.isApp,
                selectable: GrantRequester(process: process) != nil
            )
        }
    }

    /// The text of the Touch ID or password prompt: the last place where the user sees what they allow.
    public func authenticationReason(duration: Int, requester: Int?) -> String {
        let key = "the key \u{201C}\(request.secret.name)\u{201D}"
        guard request.purpose != nil, !request.forwarded else {
            return "allow one unverified request with \(key)"
        }
        let action = purpose.prefix(1).lowercased() + purpose.dropFirst()
        if case .grant(let index, _) = decision(duration: duration, requester: requester) {
            let process = requesters[index]
            return "allow \(process.name) (\(process.path)) to \(action) with \(key) for \(durations[duration].label)"
        }
        return "allow this request to \(action) with \(key) once"
    }

    /// The decision for the user's choice.
    /// - Parameters:
    ///   - duration: Index into `durations`.
    ///   - requester: Index into `requesters`, or `nil`.
    public func decision(duration: Int, requester: Int?) -> GrantDecision {
        guard durations.indices.contains(duration), let seconds = durations[duration].seconds,
              let requester, requesters.indices.contains(requester), requesters[requester].selectable else {
            return .once
        }
        return .grant(requesterIndex: requester, duration: seconds)
    }

}
