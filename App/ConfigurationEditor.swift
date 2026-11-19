import SwiftUI
import SwiftyXrayKit

struct ConfigurationEditor: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var store: SimpleStore
    @State var configuration: SimpleConfiguration
    var canCaptureDNS = true
    var isNewConfiguration = false
    var onSave: (SimpleConfiguration) throws -> Void
    @State private var error: String?
    @State private var importError: String?
    @State private var importedJSON = false
    @State private var importedResolver = false
    @State private var newResolver = ""
    @State private var capturingDNS = false
    @State private var dnsCaptureMessage: String?
    @State private var currentDNSServers: [String] = []
    @FocusState private var focusedField: String?

    var body: some View {
        NavigationStack {
            Form {
                if configuration.mode == .amnezia { amneziaFields }
                else {
                    clipboardImport
                    if configuration.mode == .turn { turnFields } else { dnsFields }
                }
                if let error { Section { Label(error, systemImage: "exclamationmark.circle").foregroundStyle(.red).font(.subheadline) } }
            }
            .scrollDismissesKeyboard(.interactively)
            .navigationTitle(configuration.mode.title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItemGroup(placement: .keyboard) {
                    Spacer()
                    Button("Done") { focusedField = nil }.accessibilityIdentifier("finishConfigurationInput")
                }
            }
            .alert("Could not paste JSON", isPresented: Binding(
                get: { importError != nil }, set: { if !$0 { importError = nil } }
            )) {
                Button("OK", role: .cancel) { importError = nil }
            } message: { Text(importError ?? "") }
            .task {
                if configuration.mode == .dns && canCaptureDNS {
                    await captureDNS(selectFirst: isNewConfiguration, automatic: true)
                }
            }
            .safeAreaInset(edge: .bottom) {
                Button(action: save) {
                    Text("Save").font(.system(size: 17, weight: .semibold)).frame(maxWidth: .infinity).padding(.vertical, 16)
                }
                .buttonStyle(.borderedProminent).buttonBorderShape(.roundedRectangle(radius: 16))
                .accessibilityIdentifier("saveConfiguration").padding(.horizontal, 20).padding(.vertical, 12)
                .background(.regularMaterial)
            }
        }.presentationDetents([.large]).presentationDragIndicator(.visible)
    }

    private var amneziaFields: some View {
        Section {
            PasteButton(payloadType: String.self) { values in
                guard let text = values.first else { return }
                do {
                    var value = configuration; value.amneziaKey = text
                    configuration = try value.validated(forConnection: true)
                    importedJSON = true; error = nil
                } catch { self.error = error.localizedDescription }
            }.accessibilityLabel("Paste Amnezia key").accessibilityIdentifier("pasteAmneziaKey")
            TextEditor(text: Binding(get: { configuration.amneziaKey ?? "" }, set: { configuration.amneziaKey = $0 }))
                .font(.system(.caption, design: .monospaced)).frame(minHeight: 140)
                .textInputAutocapitalization(.never).autocorrectionDisabled()
                .focused($focusedField, equals: "amneziaKey")
                .accessibilityLabel("Amnezia connection key").accessibilityIdentifier("amneziaKey")
            if importedJSON {
                Label("Key imported. Tap Save.", systemImage: "checkmark.circle")
                    .font(.caption).foregroundStyle(.secondary)
                Text(configuration.amneziaName ?? "Amnezia").font(.subheadline)
            }
        } header: { Text("Connection key") } footer: {
            Text("Paste the vpn:// key shared from Amnezia, or an AmneziaWG configuration. Your split tunneling rules apply automatically.")
        }
    }

    private var clipboardImport: some View {
        Section {
            HStack {
                Text("JSON settings")
                Spacer()
                PasteButton(payloadType: String.self) { values in
                    guard let text = values.first else { return }
                    importJSON(text)
                }
                .labelStyle(.titleAndIcon)
                .accessibilityLabel("Paste JSON")
                .accessibilityIdentifier("pasteConfigurationJSON")
            }
            if importedJSON {
                Label("Fields filled in. Tap Save.", systemImage: "checkmark.circle")
                    .font(.caption).foregroundStyle(.secondary)
            }
        } footer: { Text("Copy the connection settings JSON and tap Paste.") }
    }

    private func importJSON(_ text: String) {
        focusedField = nil
        do {
            let result = try ConfigurationJSONImporter.apply(text, to: configuration)
            configuration = result.configuration
            importedResolver = result.includesResolver
            importedJSON = true
            error = nil
        } catch { importError = error.localizedDescription }
    }

    private var turnFields: some View {
        Group {
            Section {
                field("VK call link", placeholder: "https://vk.com/call/join/…", text: $configuration.callLink, id: "callLink", keyboard: .URL)
                field("Server address", placeholder: "203.0.113.10:56010", text: $configuration.server, id: "turnServer")
            } footer: { Text("The link must point to an active call. The default server port is 56010.") }
            Section {
                field("UUID VLESS", placeholder: "Your server's UUID", text: $configuration.vlessID, id: "vlessID")
                field("Transport key", placeholder: "64 characters or leave blank", text: $configuration.wrapKey, id: "wrapKey")
            } footer: {
                Text("A UUID is required to connect. The transport key must match the server. Leave it blank if the server does not use wrapping.")
            }
        }
    }

    private var dnsFields: some View {
        Group {
            Section {
                field("Tunnel address", placeholder: "tunnel.example.com", text: $configuration.dns.domain, id: "dnsDomain")
                field("Public key", placeholder: "64 hexadecimal characters", text: $configuration.dns.publicKey, id: "dnsKey")
                Picker("Mode", selection: $configuration.dns.tunnelType) {
                    Text("SOCKS5").tag("socks5")
                    Text("SSH").tag("ssh")
                }.accessibilityIdentifier("dnsTunnelType")
            } footer: { Text("The mode must match your DNSTT server.") }
            Section {
                Picker("Parallel streams", selection: $configuration.dns.sessionCount) {
                    ForEach(ManagedDNSSettings.sessionCounts, id: \.self) { count in
                        Text("\(count)").tag(count)
                    }
                }.accessibilityIdentifier("dnsSessionCount")
            } header: { Text("Acceleration") } footer: {
                Text("The default is 4. Parallel streams download data simultaneously. Reduce the number if the connection is unstable.")
            }
            dnsResolvers
            if configuration.dns.tunnelType == "ssh" {
                Section("SSH access") {
                    field("User", placeholder: "Username", text: $configuration.dns.sshUsername, id: "sshUser")
                    SecureField("Password", text: $configuration.dns.sshPassword)
                        .focused($focusedField, equals: "sshPassword").accessibilityIdentifier("sshPassword")
                    field("Server fingerprint", placeholder: "SHA256:…", text: $configuration.dns.sshHostKey, id: "sshHostKey")
                    DisclosureGroup("Private key instead of password") {
                        TextEditor(text: $configuration.dns.sshPrivateKey)
                            .font(.system(.caption, design: .monospaced)).frame(minHeight: 120)
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                            .focused($focusedField, equals: "sshKey")
                            .accessibilityLabel("OpenSSH private key")
                    }
                }
            }
            Section {
                Toggle("Separate DNS for Wi-Fi", isOn: $configuration.dns.useWiFiResolver)
                    .accessibilityIdentifier("wifiDNSOverride")
                if configuration.dns.useWiFiResolver {
                    field("Wi-Fi DNS", placeholder: "8.8.8.8", text: $configuration.dns.wifiResolver,
                          id: "wifiDNSResolver")
                }
            } footer: {
                if configuration.dns.useWiFiResolver {
                    Text("This server is used on Wi-Fi. Cellular connections use the DNS server selected above. Switching is automatic.")
                }
            }
        }
    }

    private var dnsResolvers: some View {
        Section("DNS servers") {
            Toggle("Auto-detect DNS before connecting", isOn: $configuration.dns.autoDetectResolver)
                .accessibilityIdentifier("autoDetectDNSBeforeConnecting")
            field("Selected DNS", placeholder: "1.1.1.1:53", text: $configuration.dns.resolver, id: "dnsResolver")
            Button {
                focusedField = nil
                Task { await captureDNS(selectFirst: true) }
            } label: {
                HStack {
                    Label("Detect current network DNS", systemImage: "antenna.radiowaves.left.and.right")
                    if capturingDNS { Spacer(); ProgressView() }
                }
            }.disabled(capturingDNS || !canCaptureDNS).accessibilityIdentifier("captureDNS")
            if !canCaptureDNS {
                Text("Disconnect VPN to detect your carrier's or Wi-Fi network's DNS.").font(.caption).foregroundStyle(.secondary)
            }
            if let dnsCaptureMessage { Text(dnsCaptureMessage).font(.caption).foregroundStyle(.secondary) }
            ForEach(resolvers, id: \.self) { address in
                HStack {
                    Button {
                        configuration.dns.resolver = address
                    } label: {
                        HStack {
                            Image(systemName: configuration.dns.resolver == address ? "checkmark.circle.fill" : "circle")
                            VStack(alignment: .leading) {
                                Text(address).font(.system(.subheadline, design: .monospaced))
                                if currentDNSServers.contains(address) { Text("Current network").font(.caption).foregroundStyle(.secondary) }
                            }
                            Spacer()
                        }
                    }.buttonStyle(.plain).accessibilityIdentifier("selectDNS_\(address)")
                    Button {
                        store.forgetDNSServer(address)
                        configuration.dns.savedResolvers.removeAll { $0 == address }
                        currentDNSServers.removeAll { $0 == address }
                    } label: { Image(systemName: "minus.circle").foregroundStyle(.red) }
                        .buttonStyle(.borderless).accessibilityLabel("Delete DNS \(address)")
                }
            }
            HStack {
                TextField("Add IP or IP:port", text: $newResolver)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                    .focused($focusedField, equals: "newDNSResolver").accessibilityIdentifier("newDNSResolver")
                Button("Add") { addResolver() }.disabled(newResolver.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    .accessibilityIdentifier("addDNSResolver")
            }
            Text("On cellular networks, this is your carrier's DNS. On Wi-Fi, it is the network's DNS. The saved list is shared by all DNS profiles.")
                .font(.caption).foregroundStyle(.secondary)
            Text("When auto-detect is enabled, the current network's DNS is selected before connecting. Separate DNS for Wi-Fi takes priority. If detection fails, the selected DNS is used.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private var resolvers: [String] {
        (store.savedDNSServers + configuration.dns.savedResolvers + currentDNSServers).reduce(into: []) { list, address in
            if !list.contains(address) { list.append(address) }
        }
    }

    @MainActor private func captureDNS(selectFirst: Bool, automatic: Bool = false) async {
        guard canCaptureDNS, !capturingDNS else { return }
        capturingDNS = true
        defer { capturingDNS = false }
        let addresses = await Task.detached(priority: .userInitiated) { SystemDNSResolver.servers() }.value
        guard !Task.isCancelled else { return }
        let normalized = addresses.compactMap { try? ManagedDNSSettings.normalizeResolver($0) }
        currentDNSServers = normalized
        if normalized.isEmpty {
            dnsCaptureMessage = "The system did not return this network's DNS. Add an address manually."
        } else {
            do {
                try store.rememberDNSServers(normalized)
                if selectFirst, !(automatic && importedResolver), let first = normalized.first {
                    configuration.dns.resolver = first
                }
                dnsCaptureMessage = "The current network's DNS servers have been added."
            } catch { self.error = error.localizedDescription }
        }
    }

    private func addResolver() {
        do {
            let address = try ManagedDNSSettings.normalizeResolver(newResolver)
            try store.rememberDNSServers([address])
            configuration.dns.resolver = address
            newResolver = ""; focusedField = nil
        } catch { self.error = error.localizedDescription }
    }

    private func field(_ label: String, placeholder: String, text: Binding<String>, id: String, keyboard: UIKeyboardType = .asciiCapable) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(label).font(.caption.weight(.medium)).foregroundStyle(.secondary)
            TextField(placeholder, text: text).font(.body)
                .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(keyboard)
                .focused($focusedField, equals: id).submitLabel(.done).onSubmit { focusedField = nil }
                .accessibilityLabel(label).accessibilityIdentifier(id)
        }.padding(.vertical, 5)
    }

    private func save() {
        focusedField = nil
        do {
            if configuration.mode == .dns {
                let address = try ManagedDNSSettings.normalizeResolver(configuration.dns.resolver)
                configuration.dns.savedResolvers = resolvers.filter { $0 != address }
                try store.rememberDNSServers([address])
            }
            try onSave(configuration); dismiss()
        }
        catch { self.error = error.localizedDescription }
    }
}
