import Foundation
import Observation
import SecretKit

/// Collects requests that need the user's decision, for an approval window to show.
///
/// Requests that are the same (key, purpose, and requester chain apart from the connecting process, e.g. two parallel
/// ssh connections of one agent) share one pending item and get the same decision. Requests without a purpose are
/// never merged. A request that nobody decides is denied after the timeout.
@MainActor @Observable
public final class GrantApprovalCenter: GrantApprover {

    @MainActor @Observable
    public final class Item: Identifiable {
        public let id = UUID()
        public let request: GrantRequest
        fileprivate var continuations: [CheckedContinuation<GrantDecision, Never>]
        @ObservationIgnored fileprivate var timeoutTask: Task<Void, Never>?

        /// How many requests wait for this item's decision.
        public var requestCount: Int { continuations.count }

        fileprivate init(request: GrantRequest, continuation: CheckedContinuation<GrantDecision, Never>) {
            self.request = request
            self.continuations = [continuation]
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
                item.continuations.append(continuation)
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
    /// A grant to the connecting process (index 0) applies to the first request only; merged requests come from other
    /// connecting processes, so they are allowed once.
    public func resolve(_ item: Item, with decision: GrantDecision) {
        guard let index = pending.firstIndex(where: { $0.id == item.id }) else { return }
        pending.remove(at: index)
        item.timeoutTask?.cancel()
        let continuations = item.continuations
        item.continuations = []
        for (position, continuation) in continuations.enumerated() {
            if position > 0, case .grant(requesterIndex: 0, _) = decision {
                continuation.resume(returning: .once)
            } else {
                continuation.resume(returning: decision)
            }
        }
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
        let ancestors: [String]
    }

    static func mergeKey(_ request: GrantRequest) -> MergeKey? {
        guard let purpose = request.purpose, let connecting = request.provenance.chain.first else { return nil }
        let ancestors = request.provenance.chain.dropFirst().map { "\($0.pid)@\($0.startTime?.timeIntervalSince1970 ?? -1)" }
        return MergeKey(
            secret: request.secret.id,
            purpose: purpose,
            forwarded: request.forwarded,
            connectingPath: connecting.path,
            connectingSigned: connecting.validSignature,
            ancestors: ancestors
        )
    }

}
