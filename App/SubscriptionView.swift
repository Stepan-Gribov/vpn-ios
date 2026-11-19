import SwiftUI

struct SubscriptionView: View {
    @State private var startsWithAdd: Bool

    init(adding: Bool) { _startsWithAdd = State(initialValue: adding) }

    var body: some View {
        if startsWithAdd { AddSubscriptionView() }
        else { SubscriptionListView() }
    }
}

private struct AddSubscriptionView: View {
    @EnvironmentObject private var panel: PanelManager
    @Environment(\.dismiss) private var dismiss
    @FocusState private var keyFocused: Bool

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    if panel.addition == .added {
                        VStack(spacing: 16) {
                            Image(systemName: "checkmark.circle.fill")
                                .font(.system(size: 48)).foregroundStyle(.green)
                                .accessibilityHidden(true)
                            Text("Subscription added").font(.title2.bold())
                                .accessibilityIdentifier("subscriptionAdded")
                            Text("Your connections are ready.").foregroundStyle(.secondary)
                            Button("Done") { dismiss() }
                                .buttonStyle(.borderedProminent).controlSize(.large)
                                .accessibilityIdentifier("subscriptionAddedDone")
                        }
                        .multilineTextAlignment(.center).frame(maxWidth: .infinity).padding(.vertical, 24)
                    } else {
                        VStack(alignment: .leading, spacing: 10) {
                            Text("Subscription key").font(.subheadline.weight(.medium))
                            TextField("4 letters", text: Binding(get: { panel.activationText }, set: panel.updateSubscriptionKey))
                                .font(.system(size: 28, weight: .semibold, design: .monospaced))
                                .multilineTextAlignment(.center)
                                .textInputAutocapitalization(.characters).autocorrectionDisabled()
                                .keyboardType(.asciiCapable).submitLabel(.go)
                                .focused($keyFocused).privacySensitive()
                                .padding(.vertical, 14).padding(.horizontal, 16)
                                .background(Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 12))
                                .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(keyFocused ? Color.accentColor : Color.secondary.opacity(0.25)))
                                .disabled(panel.busy)
                                .accessibilityLabel("Subscription key").accessibilityIdentifier("activationInput")
                                .onSubmit { add() }
                            Text("Enter the 4 English letters supplied with your subscription.")
                                .font(.footnote).foregroundStyle(.secondary)
                        }
                        if case .failed(let message) = panel.addition {
                            Text(message).font(.callout).foregroundStyle(.red)
                                .accessibilityIdentifier("subscriptionError")
                        }
                        Button { add() } label: {
                            HStack(spacing: 10) {
                                if panel.isAddingSubscription { ProgressView().tint(.white) }
                                Text(panel.isAddingSubscription ? "Adding…" : "Add").fontWeight(.semibold)
                            }.frame(maxWidth: .infinity, minHeight: 26)
                        }
                        .buttonStyle(.borderedProminent).controlSize(.large)
                        .disabled(!panel.canAddSubscription)
                        .accessibilityIdentifier("activateAccess")
                        if panel.isAddingSubscription {
                            Text(panel.progress.isEmpty ? "Adding subscription…" : panel.progress)
                                .font(.footnote).foregroundStyle(.secondary)
                                .accessibilityIdentifier("subscriptionAdding")
                        }
                    }
                }
                .frame(maxWidth: 420).padding(24).frame(maxWidth: .infinity)
            }
            .scrollDismissesKeyboard(.interactively)
            .background(Color(uiColor: .systemGroupedBackground))
            .navigationTitle("Add subscription").navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(panel.isAddingSubscription ? "Cancel" : "Close") {
                        if panel.isAddingSubscription { panel.cancel() }
                        dismiss()
                    }.accessibilityIdentifier("closeSubscriptionAddition")
                }
            }
            .task { panel.prepareSubscriptionForm(); keyFocused = panel.activationText.isEmpty }
            .onChange(of: panel.addition) { value in
                if value == .added || value == .adding { keyFocused = false }
            }
        }
    }

    private func add() {
        guard panel.canAddSubscription else { return }
        keyFocused = false
        panel.addSubscription()
    }
}

private struct SubscriptionListView: View {
    @EnvironmentObject private var panel: PanelManager
    @Environment(\.dismiss) private var dismiss
    @State private var adding = false
    @State private var removing: PanelSubscription?

    var body: some View {
        NavigationStack {
            TimelineView(.periodic(from: .now, by: 1)) { context in
                Form {
                    if panel.reconnectRecommended {
                        Section {
                            Text("Updated settings are ready.")
                            Button("Reconnect to apply settings") { panel.reconnectToApplySettings() }
                        }
                    }
                    if panel.busy {
                        Section {
                            HStack { ProgressView(); Text(panel.progress.isEmpty ? "Updating…" : panel.progress).accessibilityIdentifier("subscriptionTransportStatus") }
                            Button("Cancel", role: .cancel) { panel.cancel() }
                        }
                    }
                    if let error = panel.error {
                        Section {
                            Text(error).foregroundStyle(.red).accessibilityIdentifier("subscriptionError")
                            Button("Dismiss error") { panel.error = nil }
                        }
                    }
                    ForEach(panel.subscriptions) { sub in
                        Section {
                            LabeledContent("Subscription code", value: sub.subscriptionCode ?? "—")
                                .textSelection(.enabled).accessibilityIdentifier("subscriptionCodeRow")
                            LabeledContent("Status", value: sub.statusText(now: Int64(context.date.timeIntervalSince1970)))
                            LabeledContent("Expires", value: sub.package.expiresAt.map { Date(timeIntervalSince1970: Double($0)).formatted(date: .abbreviated, time: .shortened) } ?? "Unlimited")
                            LabeledContent("Last update", value: Date(timeIntervalSince1970: Double(sub.lastSync)).formatted(date: .abbreviated, time: .shortened))
                            LabeledContent("Connections", value: String(sub.package.profiles.count))
                            if sub.needsActivation { Text("Add this subscription again using its key. Your saved settings are retained.").font(.callout) }
                            Button("Refresh subscription") { panel.refresh(sub) }.disabled(sub.needsActivation || panel.busy)
                            Button("Remove subscription", role: .destructive) { removing = sub }
                        } header: { Text(sub.package.clientName) }
                    }
                }
            }
            .navigationTitle("Subscriptions").navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button { adding = true } label: { Label("Add subscription", systemImage: "plus") }
                        .disabled(panel.busy).accessibilityIdentifier("addSubscription")
                }
                ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
            }
            .task { panel.reload(); panel.recoverSubscriptionCodes() }
            .sheet(isPresented: $adding) { AddSubscriptionView() }
            .confirmationDialog("Remove subscription from this device?", isPresented: Binding(get: { removing != nil }, set: { if !$0 { removing = nil } }), titleVisibility: .visible) {
                Button("Remove subscription", role: .destructive) { if let sub = removing { panel.remove(sub); removing = nil } }
            } message: { Text("Its assigned profiles and token will be deleted. Manual profiles and built-in DNS are retained.") }
        }
    }
}
