import Foundation
import Observation
import SecretKit

/// Collects requests that need the user's decision, for an approval window to show.
///
/// Requests that are the same (key, purpose, connecting binary, and the chain from the default requester upward, e.g.
/// two parallel ssh connections of one agent through different shells) share one pending item and get the same
/// decision. Requests without a purpose or without a default requester are never merged. A request that nobody decides is denied after the timeout.
@MainActor @Observable
public final class GrantApprovalCenter: GrantApprover {

    @MainActor @Observable
    public final class Item: Identifiable {
        public let id = UUID()
        /// The request the window shows.
        public let request: GrantRequest
        /// The shown request first, then merged ones.
        fileprivate var waiting: [(request: GrantRequest, continuation: CheckedContinuation<GrantDecision, Never>)]
        @ObservationIgnored fileprivate var timeoutTask: Task<Void, Never>?

        /// How many requests wait for this item's decision.
        public var requestCount: Int { waiting.count }

        fileprivate init(request: GrantRequest, continuation: CheckedContinuation<GrantDecision, Never>) {
            self.request = request
            self.waiting = [(request, continuation)]
        }
    }

    /// Pending items, oldest first.
    public private(set) var pending: [Item] = []
    /// Called when a new item is pending, e.g. to open the approval window.
    public var onPendingRequest: (() -> Void)?

    private let timeout: Duration

    public init(timeout: Duration = .seconds(120)) {
        self.timeout = timeout
    }

    public func decide(_ request: GrantRequest) async -> GrantDecision {
        await withCheckedContinuation { continuation in
            if let key = Self.mergeKey(request), let item = pending.first(where: { Self.mergeKey($0.request) == key }) {
                item.waiting.append((request, continuation))
                return
            }
            let item = Item(request: request, continuation: continuation)
            pending.append(item)
            onPendingRequest?()
            item.timeoutTask = Task { [timeout, weak self, weak item] in
                try? await Task.sleep(for: timeout)
                guard !Task.isCancelled, let item else { return }
                self?.resolve(item, with: .deny)
            }
        }
    }

    /// Answers all requests of a pending item. Does nothing if the item is no longer pending.
    ///
    /// The decision refers to the shown request's process chain. Merged requests get it translated to their own chain,
    /// see ``translate(_:from:to:)``.
    public func resolve(_ item: Item, with decision: GrantDecision) {
        guard let index = pending.firstIndex(where: { $0.id == item.id }) else { return }
        pending.remove(at: index)
        item.timeoutTask?.cancel()
        let waiting = item.waiting
        item.waiting = []
        for (position, entry) in waiting.enumerated() {
            entry.continuation.resume(returning: position == 0 ? decision : Self.translate(decision, from: item.request, to: entry.request))
        }
    }

    /// Merged requests share the chain from the default requester upward, but the processes below it differ, and so
    /// can the chain length. A grant to the default requester or above moves to the same process in the other chain;
    /// a grant below it would name a process the user did not see, so it becomes a one-time approval.
    static func translate(_ decision: GrantDecision, from shown: GrantRequest, to merged: GrantRequest) -> GrantDecision {
        guard case .grant(let index, let duration) = decision else { return decision }
        guard let shownDefault = shown.defaultRequesterIndex, let mergedDefault = merged.defaultRequesterIndex,
              index >= shownDefault else {
            return .once
        }
        return .grant(requesterIndex: mergedDefault + (index - shownDefault), duration: duration)
    }

    /// Denies all pending requests, e.g. when the user closes the window.
    public func denyAll() {
        for item in pending {
            resolve(item, with: .deny)
        }
    }

    struct MergeKey: Hashable {
        let secret: AnyHashable
        let purpose: GrantPurpose
        let forwarded: Bool
        /// The connecting process may differ (e.g. two ssh processes), but must be the same binary.
        let connectingPath: String
        let connectingSigned: Bool
        /// The default requester and its ancestors.
        let requester: [String]
    }

    static func mergeKey(_ request: GrantRequest) -> MergeKey? {
        let chain = request.provenance.chain
        // Requests in advance carry more than the window shows for the first request (reason, further host keys).
        guard !request.advance, let purpose = request.purpose, let connecting = chain.first,
              let index = request.defaultRequesterIndex, chain.indices.contains(index) else { return nil }
        let requester = chain[index...].map { "\($0.pid)@\($0.startTime?.timeIntervalSince1970 ?? -1)" }
        return MergeKey(
            secret: request.secret.id,
            purpose: purpose,
            forwarded: request.forwarded,
            connectingPath: connecting.path,
            connectingSigned: connecting.validSignature,
            requester: requester
        )
    }

}
