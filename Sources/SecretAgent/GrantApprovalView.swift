import SwiftUI
import LocalAuthentication
import SecretKit
import SecretAgentKit

struct GrantApprovalViewIdentifier: Codable, Hashable {}

/// Asks the user about the oldest pending grant request. Approving needs Touch ID or the login password.
struct GrantApprovalView: View {

    let center: GrantApprovalCenter
    @Environment(\.dismissWindow) private var dismiss

    var body: some View {
        Group {
            if let item = center.pending.first {
                GrantApprovalItemView(item: item, center: center, waiting: center.pending.count - 1)
                    .id(item.id)
            } else {
                Color.clear.onAppear { dismiss() }
            }
        }
        .frame(width: 520)
        .onChange(of: center.pending.isEmpty) { _, isEmpty in
            if isEmpty { dismiss() }
        }
        // Closing the window is a "no" to everything it would show; ssh should not wait for the timeout.
        .onDisappear { center.denyAll() }
    }

}

private struct GrantApprovalItemView: View {

    let item: GrantApprovalCenter.Item
    let center: GrantApprovalCenter
    let waiting: Int
    let presentation: GrantPresentation
    @State private var requester: Int?
    @State private var duration: Int
    @State private var authenticating = false
    /// Allow stays disabled for a moment after a new request appears, so a click or key press meant for something
    /// else cannot approve it.
    @State private var armed = false

    init(item: GrantApprovalCenter.Item, center: GrantApprovalCenter, waiting: Int) {
        self.item = item
        self.center = center
        self.waiting = waiting
        let presentation = GrantPresentation(item.request)
        self.presentation = presentation
        _requester = State(initialValue: item.request.defaultRequesterIndex)
        _duration = State(initialValue: presentation.defaultDuration)
    }

    private var grants: Bool {
        presentation.durations[duration].seconds != nil
    }

    private var canAllow: Bool {
        guard armed, !authenticating else { return false }
        guard grants else { return true }
        guard let requester else { return false }
        return presentation.requesters[requester].selectable
    }

    private static let allowLabel: String = {
        let context = LAContext()
        _ = unsafe context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        return context.biometryType == .touchID ? "Allow with Touch ID" : "Allow with Password"
    }()

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(presentation.title)
                .font(.headline)
            VStack(alignment: .leading, spacing: 4) {
                Text(presentation.purpose)
                    .font(.title3)
                ForEach(presentation.hostKeyFingerprints, id: \.self) { fingerprint in
                    Text("Host key \(fingerprint)")
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                }
            }
            if let reason = presentation.reason {
                // In its own box, so the requester's text cannot pass for the app's text.
                GroupBox("Reason given by the requester (not verified)") {
                    Text(reason)
                        .font(.callout)
                        .lineLimit(4)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            if presentation.durations.count == 1 {
                Label("This request can only be allowed once.", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
            }

            GroupBox("Requested by") {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(presentation.requesters.reversed()) { process in
                        requesterRow(process)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            if grants, let requester {
                Text("The grant covers only this key and the purpose above\(presentation.hostKeyFingerprints.count > 1 ? " (all listed host keys)" : ""), for \(presentation.requesters[requester].name) (pid \(String(presentation.requesters[requester].pid))) and every process it starts.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Picker("Allow for", selection: $duration) {
                ForEach(Array(presentation.durations.enumerated()), id: \.offset) { index, option in
                    Text(option.label).tag(index)
                }
            }
            .disabled(presentation.durations.count == 1)

            HStack {
                if item.requestCount > 1 {
                    Text("\(item.requestCount) identical requests")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                if waiting > 0 {
                    Text("\(waiting) more waiting")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Deny", role: .cancel) {
                    center.resolve(item, with: .deny)
                }
                .keyboardShortcut(.cancelAction)
                Button(Self.allowLabel) {
                    Task { await approve() }
                }
                .disabled(!canAllow)
            }
        }
        .padding(20)
        .task {
            try? await Task.sleep(for: .seconds(1))
            armed = true
        }
    }

    @ViewBuilder
    private func requesterRow(_ process: GrantPresentation.Requester) -> some View {
        let selected = requester == process.index
        HStack(alignment: .top) {
            Image(systemName: selected ? "largecircle.fill.circle" : "circle")
                .foregroundStyle(process.selectable && grants ? Color.accentColor : Color.secondary)
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 6) {
                    Text(process.name).fontWeight(selected ? .semibold : .regular)
                    Text("pid \(String(process.pid))").foregroundStyle(.secondary)
                    if !process.validSignature {
                        Text("unsigned").foregroundStyle(.orange)
                    }
                }
                .font(.callout)
                Text(process.path)
                    .font(.caption2.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        }
        .contentShape(Rectangle())
        .onTapGesture {
            if process.selectable && grants {
                requester = process.index
            }
        }
        .opacity(process.selectable || !grants ? 1 : 0.5)
    }

    private func approve() async {
        authenticating = true
        defer { authenticating = false }
        let context = LAContext()
        do {
            let reason = presentation.authenticationReason(duration: duration, requester: requester)
            guard try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) else { return }
        } catch {
            return
        }
        center.resolve(item, with: presentation.decision(duration: duration, requester: requester))
    }

}
