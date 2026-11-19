import SwiftUI
import UniformTypeIdentifiers

/// The system save dialog writes this immutable JSON without a sharing extension
/// or a temporary file whose lifetime can race the recipient.
struct BackupExportDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.json] }
    static var writableContentTypes: [UTType] { [.json] }
    let data: Data

    init(data: Data) { self.data = data }
    init(configuration: ReadConfiguration) throws {
        guard let data = configuration.file.regularFileContents else { throw CocoaError(.fileReadCorruptFile) }
        self.data = data
    }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: data)
    }
    static func prepare(_ backup: ApplicationBackup) async throws -> Self {
        try await Task.detached(priority: .userInitiated) {
            Self(data: try backup.encoded())
        }.value
    }
}

struct BackupPreview: View {
    @Environment(\.dismiss) private var dismiss
    let backup: ApplicationBackup
    let onConfirm: () async throws -> Void
    @State private var restoring = false
    @State private var error: String?

    var body: some View {
        NavigationStack {
            List {
                Section("Backup contents") {
                    LabeledContent("Amnezia profiles", value: String(backup.amneziaCount))
                    LabeledContent("TURN profiles", value: String(backup.turnCount))
                    LabeledContent("DNS profiles", value: String(backup.dnsCount))
                    LabeledContent("Saved DNS servers", value: String(backup.savedDNSServers.count))
                    LabeledContent("Bypass addresses", value: String(backup.splitTunneling.bypassEntries.count))
                    LabeledContent("Tunnel addresses", value: String(backup.splitTunneling.tunnelEntries.count))
                    LabeledContent("Split tunneling", value: backup.splitTunneling.mode.title)
                    LabeledContent("Auto-captcha", value: backup.autoCaptcha ? "On" : "Off")
                    LabeledContent("Auto-recovery", value: backup.autoRecovery ? "On" : "Off")
                    LabeledContent("TURN background check", value: TURNHealthCheckPolicy.label(backup.effectiveTURNCheckInterval))
                }
                if !backup.profiles.isEmpty {
                    Section("Profiles") {
                        ForEach(backup.profiles.prefix(5)) { profile in
                            Label(profile.title, systemImage: profile.mode == .turn ? "phone" : "network")
                        }
                        if backup.profiles.count > 5 { Text("And \(backup.profiles.count - 5)").foregroundStyle(.secondary) }
                    }
                }
                Section {
                    Text("All current profiles and settings will be replaced. VPN will disconnect. Connect to your chosen profile manually after importing.")
                        .foregroundStyle(.secondary)
                }
            }
            .safeAreaInset(edge: .bottom) {
                Button(action: confirm) {
                    HStack {
                        if restoring { ProgressView().tint(.white) }
                        Text(restoring ? "Importing…" : "Replace and import")
                    }.frame(maxWidth: .infinity).padding(.vertical, 8)
                }.buttonStyle(.borderedProminent).padding()
                    .background(.regularMaterial)
                    .accessibilityIdentifier("confirmApplicationBackup").disabled(restoring)
            }
            .navigationTitle("Import settings").navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") { dismiss() }.disabled(restoring).accessibilityIdentifier("cancelApplicationBackup")
            } }
            .interactiveDismissDisabled(restoring)
            .alert("Import failed", isPresented: Binding(get: { error != nil }, set: { if !$0 { error = nil } })) {
                Button("OK", role: .cancel) { error = nil }
            } message: { Text(error ?? "") }
        }.presentationDetents([.large]).presentationDragIndicator(.visible)
    }

    private func confirm() {
        restoring = true
        Task {
            do { try await onConfirm(); dismiss() }
            catch { self.error = error.localizedDescription }
            restoring = false
        }
    }
}
