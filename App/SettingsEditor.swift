import SwiftUI
import UniformTypeIdentifiers

struct SettingsEditor: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var store: SimpleStore
    @ObservedObject var runtime: AppStore
    @State var autoCaptcha: Bool
    @State var autoRecovery: Bool
    @State var autoConnectOnLaunch: Bool
    @State var turnCheckInterval: Int
    @State var turnSessionCount: Int
    @State var splitTunneling: SplitTunnelSettings
    @State var amneziaSplitEnabled: Bool
    @State var fullTunnelMinutes: Int
    var onImport: (ApplicationBackup) async throws -> Void
    var onSave: (Bool, Bool, Bool, Int, SplitTunnelSettings, Bool, Int, Int) async throws -> Void
    @State private var tab = 0
    @State private var newAddress = ""
    @State private var search = ""
    @State private var showingFileImporter = false
    @State private var importing = false
    @State private var saving = false
    @State private var error: String?
    @State private var importMessage: String?
    @State private var confirmingClear = false
    @State private var detailEntry: SplitTunnelEntry?
    @State private var importingBackup = false
    @State private var pendingBackup: ApplicationBackup?
    @State private var exportDocument: BackupExportDocument?
    @State private var exportFilename = "TnDtun-backup"
    @State private var showingFileExporter = false
    @State private var exporting = false
    @State private var exportMessage: String?
    @FocusState private var editingAddress: Bool

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                Picker("Settings section", selection: $tab) {
                    Text("General").tag(0)
                    Text("Split tunneling").tag(1)
                    Text("Transfer").tag(2)
                }
                .pickerStyle(.segmented).padding(.horizontal, 20).padding(.vertical, 12)
                .accessibilityIdentifier("settingsTabs")
                Form {
                    if tab == 0 { automation } else if tab == 1 { splitFields } else { transferFields }
                }.scrollDismissesKeyboard(.interactively).disabled(saving)
            }
            .navigationTitle("Settings").navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }.disabled(saving || exporting)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(saving ? "Saving…" : "Save", action: save)
                        .disabled(saving || importing || exporting).accessibilityIdentifier("saveAutomation")
                }
                ToolbarItemGroup(placement: .keyboard) {
                    Spacer(); Button("Done") { editingAddress = false }
                }
            }
            .fileImporter(isPresented: $showingFileImporter, allowedContentTypes: [.json], allowsMultipleSelection: false) { result in
                switch result {
                case .success(let urls): if let url = urls.first {
                    if importingBackup { importBackupFile(url) } else { importFile(url) }
                }
                case .failure(let failure): error = failure.localizedDescription
                }
            }
            .alert("Action failed", isPresented: Binding(get: { error != nil }, set: { if !$0 { error = nil } })) {
                Button("OK", role: .cancel) { error = nil }
            } message: { Text(error ?? "") }
            .confirmationDialog("Delete all addresses in this list?", isPresented: $confirmingClear, titleVisibility: .visible) {
                Button("Delete list", role: .destructive) {
                    splitTunneling.setEntries([], for: splitTunneling.mode); importMessage = nil
                }
            }
            .sheet(item: $detailEntry) { entry in
                NavigationStack {
                    List {
                        Section { Text(entry.address).textSelection(.enabled) }
                        if !entry.networks.isEmpty {
                            Section("IP networks") {
                                ForEach(entry.networks, id: \.self) { Text($0).font(.system(.body, design: .monospaced)).textSelection(.enabled) }
                            }
                        }
                    }.navigationTitle("Address").navigationBarTitleDisplayMode(.inline)
                        .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { detailEntry = nil } } }
                }
            }
            .fileExporter(isPresented: $showingFileExporter, document: exportDocument,
                          contentType: .json, defaultFilename: exportFilename, onCompletion: { result in
                showingFileExporter = false
                exportDocument = nil
                switch result {
                case .success: exportMessage = "Backup saved."
                case .failure(let failure): error = failure.localizedDescription
                }
            })
            .onValueChange(of: showingFileExporter) { presented in
                if !presented { exportDocument = nil }
            }
            .sheet(item: $pendingBackup) { backup in
                BackupPreview(backup: backup) {
                    try await onImport(backup)
                    dismiss()
                }
            }
            .interactiveDismissDisabled(saving || exporting)
        }.presentationDetents([.large]).presentationDragIndicator(.visible)
    }

    private var automation: some View {
        Group {
            Section {
                Toggle("Auto-connect on app restart", isOn: $autoConnectOnLaunch)
                    .accessibilityIdentifier("autoConnectOnLaunchToggle")
            } footer: {
                Text("Connects the last selected available profile once when TnDtun opens, including Amnezia. Requires VPN permission from an earlier manual connection. After a device restart, unlock it and open TnDtun. An active VPN is left running.")
            }

            Section {
                Toggle("TURN auto-recovery", isOn: $autoRecovery).accessibilityIdentifier("autoRecoveryToggle")
            } footer: {
                Text("TURN proxy only. Checks and reconnects in the background. Amnezia and DNS tunnel do not use this automation. If the TURN server is unavailable, we pause after 5 attempts and try again. Disconnect stops automatic recovery.")
            }
            Section {
                Picker("Параллельные каналы", selection: $turnSessionCount) {
                    ForEach(TURNSettings.sessionChoices, id: \.self) { count in
                        Text(count == 10 ? "10 · по умолчанию" : String(count)).tag(count)
                    }
                }.accessibilityIdentifier("turnSessionCountPicker")
                    .accessibilityValue(String(turnSessionCount))
            } header: { Text("TURN") } footer: {
                Text("При нестабильной сети можно попробовать 1, 2 или 4 канала. Скорость может снизиться. Применяется при следующем подключении; обновление подписки сохраняет выбор.")
            }
            Section {
                Picker("Background check", selection: $turnCheckInterval) {
                    ForEach(Array(Set(TURNHealthCheckPolicy.intervals + [turnCheckInterval])).sorted(), id: \.self) { seconds in
                        Text(TURNHealthCheckPolicy.label(seconds)).tag(seconds)
                    }
                }
                .pickerStyle(.menu)
                .disabled(!autoRecovery)
                .accessibilityIdentifier("turnCheckIntervalPicker")
                .accessibilityValue(TURNHealthCheckPolicy.label(turnCheckInterval))
            } header: {
                Text("TURN proxy")
            } footer: {
                Text("Checks real traffic through TURN while the app is in the background. Reconnects if the connection stops responding. Requires TURN auto-recovery. Applies after Save.")
            }
            Section { Text("Version \(Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "") (\(Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? ""))").foregroundStyle(.secondary) }
        }
    }

    private var splitFields: some View {
        Group {
            Section {
                Picker("Вернуть сплит-туннель", selection: $fullTunnelMinutes) {
                    ForEach(TemporaryFullTunnelPolicy.minutes, id: \.self) { minutes in
                        Text(minutes == 0 ? "До следующего подключения VPN" : "Через \(minutes) минут").tag(minutes)
                    }
                }.accessibilityIdentifier("fullTunnelDuration")
            } header: { Text("Всё в туннель · временно") } footer: {
                Text("Переключатель рядом с Disconnect временно снимает адресные правила. Сплит возвращается по таймеру или при следующем подключении VPN. Применение кратко прерывает открытые соединения. Во сне возврат выполняется при пробуждении расширения VPN.")
            }
            Section {
                Toggle("Сплит-туннель для Amnezia", isOn: $amneziaSplitEnabled)
                    .accessibilityIdentifier("amneziaSplitEnabled")
            } footer: {
                Text("По умолчанию сплит применяется к VK TURN proxy и Amnezia. DNS-режим использует полный туннель. Push-правила действуют отдельно.")
            }
            Section {
                Toggle("Apple push through VPN", isOn: Binding(get: { splitTunneling.pushNotifications?.apple ?? false }, set: { value in
                    var push = splitTunneling.pushNotifications ?? PushNotificationSettings(); push.apple = value; splitTunneling.pushNotifications = push
                })).accessibilityIdentifier("pushAppleVPN")
                Toggle("Google push through VPN", isOn: Binding(get: { splitTunneling.pushNotifications?.google ?? false }, set: { value in
                    var push = splitTunneling.pushNotifications ?? PushNotificationSettings(); push.google = value; splitTunneling.pushNotifications = push
                })).accessibilityIdentifier("pushGoogleVPN")
            } header: { Text("Push notifications") } footer: {
                Text("Routes push services through the selected VPN before address rules. Both address lists stay unchanged. Applies after Save and reconnect. Service rules: version 1.")
            }
            Section {
                ForEach(SplitTunnelMode.allCases) { mode in
                    Button { splitTunneling.mode = mode; importMessage = nil; search = "" } label: {
                        HStack(spacing: 12) {
                            Image(systemName: splitTunneling.mode == mode ? "largecircle.fill.circle" : "circle")
                                .foregroundStyle(splitTunneling.mode == mode ? Color.accentColor : Color.secondary)
                            Text(mode.title).foregroundStyle(.primary).frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }.accessibilityIdentifier("splitMode_" + mode.rawValue)
                        .accessibilityValue(splitTunneling.mode == mode ? "Selected" : "Not selected").disabled(importing)
                }
            } footer: {
                Text(splitTunneling.mode.detail + " Each mode has its own list. Saving changes reconnects an active tunnel.")
            }
            if splitTunneling.mode != .disabled {
                Section {
                    HStack {
                        TextField("Domain, IP or CIDR", text: $newAddress)
                            .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                            .focused($editingAddress).accessibilityIdentifier("splitAddressField").onSubmit(addManual)
                        Button(action: addManual) { Image(systemName: "plus.circle.fill").font(.title3) }
                            .disabled(newAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || importing)
                            .accessibilityLabel("Add address").accessibilityIdentifier("addSplitAddress")
                    }
                } header: { Text("Add address") } footer: { Text("For example: example.com, 203.0.113.7 or 203.0.113.0/24. Separate multiple addresses with spaces or commas.") }
                Section {
                    Button { importingBackup = false; showingFileImporter = true } label: { Label("Choose JSON file", systemImage: "doc.badge.plus") }
                        .disabled(importing).accessibilityIdentifier("importSplitJSONFile")
                    HStack {
                        Text("From clipboard")
                        Spacer()
                        PasteButton(payloadType: String.self) { values in
                            guard let text = values.first else { return }
                            importData(Data(text.utf8))
                        }.labelStyle(.iconOnly).accessibilityLabel("Paste JSON").accessibilityIdentifier("pasteSplitJSON")
                            .disabled(importing)
                    }
                    Link(destination: URL(string: "https://iplist.opencck.org/ru/")!) {
                        Label("Download address list", systemImage: "arrow.down.doc")
                    }
                    if importing { ProgressView("Reading list…") }
                    if let importMessage { Text(importMessage).foregroundStyle(.secondary).font(.subheadline) }
                } header: { Text("Import JSON") } footer: {
                    Text("New addresses are added to the current list. Domain-to-network mappings and address arrays are supported. Some networks are shared by multiple websites.")
                }
                if !splitTunneling.activeEntries.isEmpty {
                    Section {
                        TextField("Search addresses", text: $search).textInputAutocapitalization(.never).autocorrectionDisabled()
                            .accessibilityIdentifier("splitAddressSearch")
                        ForEach(visibleEntries) { entry in
                            HStack {
                                Button { detailEntry = entry } label: {
                                    VStack(alignment: .leading, spacing: 4) {
                                        Text(entry.address).foregroundStyle(.primary).lineLimit(2)
                                        if !entry.networks.isEmpty { Text("\(entry.isNetworkGroup ? "IP networks" : "Domain and IP networks"): \(entry.networks.count)").font(.caption).foregroundStyle(.secondary) }
                                    }.frame(maxWidth: .infinity, alignment: .leading)
                                }.buttonStyle(.plain).accessibilityIdentifier("splitEntry_" + entry.id)
                                Button(role: .destructive) { remove(entry) } label: { Image(systemName: "minus.circle") }
                                    .buttonStyle(.borderless).accessibilityLabel("Delete \(entry.address)")
                            }
                        }
                        if visibleEntries.isEmpty { Text("No results").foregroundStyle(.secondary) }
                        Button("Delete list", role: .destructive) { confirmingClear = true }
                    } header: { Text("Addresses: \(splitTunneling.activeEntries.count)") }
                } else {
                    Section { Text("The list is empty. \(splitTunneling.mode == .tunnelSelected ? "All internet traffic will connect directly." : "All internet traffic will use the tunnel.")").foregroundStyle(.secondary) }
                }
            }
        }
    }

    private var transferFields: some View {
        Group {
            Section {
                Button(action: exportBackup) { Label("Export all", systemImage: "square.and.arrow.up") }
                    .accessibilityIdentifier("exportApplicationBackup").disabled(importing || exporting || showingFileExporter)
                if exporting { ProgressView("Preparing backup…") }
                if let exportMessage { Text(exportMessage).foregroundStyle(.secondary).font(.subheadline) }
            } header: { Text("To another device") } footer: {
                Text("All Amnezia, TURN and DNS profiles, keys, DNS and Wi-Fi settings, both split tunneling lists and switches in one JSON file. Choose a folder, save the file and transfer it to another device. It contains keys and passwords, so share it only with people you trust.")
            }
            Section {
                Button { importingBackup = true; showingFileImporter = true } label: {
                    Label("Import from file", systemImage: "square.and.arrow.down")
                }.accessibilityIdentifier("importApplicationBackup").disabled(importing)
                HStack {
                    Text("From clipboard")
                    Spacer()
                    PasteButton(payloadType: String.self) { values in
                        if let text = values.first { readBackup(Data(text.utf8)) }
                    }.labelStyle(.iconOnly).accessibilityLabel("Paste backup")
                        .accessibilityIdentifier("pasteApplicationBackup").disabled(importing)
                }
                if importing { ProgressView("Reading backup…") }
            } header: { Text("Restore settings") } footer: {
                Text("Review the file before importing. Confirmation replaces all current profiles and settings. VPN stays disconnected; connect to your chosen profile manually.")
            }
        }
    }

    private func exportBackup() {
        guard !exporting, !showingFileExporter else { return }
        exporting = true
        exportMessage = nil
        Task { @MainActor in
            defer { exporting = false }
            do {
                let backup = try store.backupSnapshot(autoCaptcha: autoCaptcha, autoRecovery: autoRecovery,
                                                      turnCheckInterval: turnCheckInterval, autoConnectOnLaunch: autoConnectOnLaunch,
                                                      splitTunneling: splitTunneling, selectedProfileID: runtime.activeProfileId,
                                                      amneziaSplitEnabled: amneziaSplitEnabled, fullTunnelMinutes: fullTunnelMinutes, turnSessionCount: turnSessionCount)
                let document = try await BackupExportDocument.prepare(backup)
                exportFilename = "TnDtun-backup-" + String(backup.createdAt.prefix(10))
                exportDocument = document
                showingFileExporter = true
            } catch { self.error = error.localizedDescription }
        }
    }
    private func readBackup(_ data: Data) {
        importing = true
        Task {
            do { pendingBackup = try await Task.detached { try ApplicationBackup.decode(data) }.value }
            catch { self.error = error.localizedDescription }
            importing = false
        }
    }
    private func importBackupFile(_ url: URL) {
        importing = true
        Task {
            do {
                pendingBackup = try await Task.detached {
                    let scoped = url.startAccessingSecurityScopedResource()
                    defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                    if let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize, size > ApplicationBackup.maximumSize {
                        throw ConfigurationError("The backup is too large. The maximum size is 20 MB.")
                    }
                    return try ApplicationBackup.decode(Data(contentsOf: url))
                }.value
            } catch { self.error = error.localizedDescription }
            importing = false
        }
    }

    private var visibleEntries: [SplitTunnelEntry] {
        let query = search.trimmingCharacters(in: .whitespacesAndNewlines)
        return query.isEmpty ? splitTunneling.activeEntries : splitTunneling.activeEntries.filter {
            $0.address.localizedCaseInsensitiveContains(query) || $0.networks.contains(where: { $0.contains(query) })
        }
    }
    private func addManual() {
        do {
            let entries = try SplitTunnelImport.manual(newAddress)
            try merge(entries, mode: splitTunneling.mode)
            newAddress = ""; editingAddress = false
        } catch { self.error = error.localizedDescription }
    }
    private func merge(_ entries: [SplitTunnelEntry], mode: SplitTunnelMode) throws {
        let previous = mode == .bypassSelected ? splitTunneling.bypassEntries : splitTunneling.tunnelEntries
        let merged = try SplitTunnelImport.normalized(previous + entries)
        splitTunneling.setEntries(merged, for: mode)
        importMessage = "Addresses in list: \(merged.count)."
    }
    private func remove(_ entry: SplitTunnelEntry) {
        splitTunneling.setEntries(splitTunneling.activeEntries.filter { $0.id != entry.id }, for: splitTunneling.mode)
    }
    private func importData(_ data: Data) {
        let mode = splitTunneling.mode
        importing = true
        Task {
            do {
                let entries = try await Task.detached { try SplitTunnelImport.json(data) }.value
                try merge(entries, mode: mode)
            } catch { self.error = error.localizedDescription }
            importing = false
        }
    }
    private func importFile(_ url: URL) {
        let mode = splitTunneling.mode
        importing = true
        Task {
            do {
                let entries = try await Task.detached {
                    let scoped = url.startAccessingSecurityScopedResource()
                    defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                    if let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize, size > SplitTunnelImport.maximumFileSize {
                        throw SplitTunnelError(message: "The file is too large. The maximum size is 5 MB.")
                    }
                    return try SplitTunnelImport.json(Data(contentsOf: url))
                }.value
                try merge(entries, mode: mode)
            } catch { self.error = error.localizedDescription }
            importing = false
        }
    }
    private func save() {
        editingAddress = false
        saving = true
        Task {
            do {
                if !newAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && splitTunneling.mode != .disabled {
                    try merge(SplitTunnelImport.manual(newAddress), mode: splitTunneling.mode)
                    newAddress = ""
                }
                try await onSave(autoCaptcha, autoRecovery, autoConnectOnLaunch, turnCheckInterval, splitTunneling.validated(), amneziaSplitEnabled, fullTunnelMinutes, turnSessionCount)
                dismiss()
            } catch { self.error = error.localizedDescription }
            saving = false
        }
    }
}
