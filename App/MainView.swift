import SwiftUI
import SwiftyXrayKit

struct MainView: View {
    @EnvironmentObject private var store: SimpleStore
    @EnvironmentObject private var panel: PanelManager
    @EnvironmentObject private var vpn: VPNManager
    @EnvironmentObject private var runtime: AppStore
    @State private var editor: SimpleConfiguration?
    @State private var pendingDelete: SimpleConfiguration?
    @State private var showingCaptcha = false
    @State private var showingAutomation = false
    @State private var showingConnectionGuide = false
    @State private var preparing = false
    @State private var pingRequestID: UUID?
    @State private var checkingPing = false
    @State private var pingUnavailable = false
    @State private var connectionTask: Task<Void, Never>?

    private let ink = Color(red: 0.08, green: 0.12, blue: 0.22)
    private let muted = Color(red: 0.44, green: 0.48, blue: 0.55)
    private var errorMessage: String? { store.error ?? vpn.lastError ?? vpn.connectionDropMessage }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("TnDtun").font(.system(size: 25, weight: .bold)).foregroundStyle(ink)
                Spacer()
                Button { showingConnectionGuide = true } label: {
                    Image(systemName: "questionmark.circle").foregroundStyle(Color.accentColor)
                        .font(.system(size: 23)).frame(width: 44, height: 44)
                }.accessibilityLabel("Connection guide").accessibilityIdentifier("connectionGuide")
                Button { showingAutomation = true } label: {
                    Image(systemName: "gearshape").foregroundStyle(Color.accentColor)
                        .font(.system(size: 23)).frame(width: 44, height: 44)
                }.accessibilityLabel("Settings").accessibilityIdentifier("automationSettings")
            }
            .padding(.top, 18).padding(.bottom, 24)

            HStack(spacing: 12) {
                Button { panel.showingSubscription = true } label: {
                    Label(panel.subscriptions.isEmpty ? "Add subscription" : "Subscription", systemImage: "person.crop.circle.badge.checkmark")
                        .lineLimit(1).minimumScaleFactor(0.65)
                        .frame(maxWidth: .infinity).frame(height: 42)
                }.accessibilityIdentifier("openSubscription")
                Button { panel.refreshAll() } label: {
                    VStack(spacing: 1) {
                        Label("Refresh", systemImage: "arrow.clockwise")
                        if let updated = panel.lastSuccessfulUpdate {
                            Text(updated, format: .dateTime.hour().minute())
                                .font(.caption2).foregroundStyle(.secondary)
                        }
                    }
                    .lineLimit(1).minimumScaleFactor(0.65)
                    .frame(maxWidth: .infinity).frame(height: 42)
                }
                .accessibilityLabel("Refresh")
                .accessibilityValue(panel.lastSuccessfulUpdate?.formatted(date: .abbreviated, time: .shortened) ?? "")
                .accessibilityIdentifier("refreshSubscriptions")
            }.font(.callout.weight(.medium)).dynamicTypeSize(...DynamicTypeSize.xLarge)
                .buttonStyle(.bordered).padding(.bottom, 14)
            if panel.showsTransferProgress { HStack { ProgressView(); Text(panel.progress.isEmpty ? "Updating subscription…" : panel.progress).font(.caption).accessibilityIdentifier("subscriptionTransportStatus"); Spacer(); Button("Cancel") { panel.cancel() } }.padding(.bottom, 12) }
            if panel.reconnectRecommended {
                Button("Reconnect to apply updated settings") { panel.reconnectToApplySettings() }
                    .font(.caption).padding(.bottom, 12)
            }
            statusPanel.padding(.bottom, 24)

            Picker("Connection mode", selection: $store.mode) {
                ForEach(TunnelMode.allCases) { mode in Text(mode.title).tag(mode) }
            }
            .pickerStyle(.segmented).accessibilityIdentifier("modePicker")
            .padding(.bottom, 28)

            HStack {
                Text("Configurations").font(.system(size: 18, weight: .semibold)).foregroundStyle(ink)
                if !store.visibleConfigurations.isEmpty {
                    Text("\(store.visibleConfigurations.count)").font(.caption.weight(.semibold))
                        .foregroundStyle(muted).padding(.horizontal, 7).padding(.vertical, 4)
                        .background(Color.black.opacity(0.04), in: Capsule())
                }
                Spacer()
                if !store.visibleConfigurations.isEmpty { addButton }
            }.padding(.bottom, 14)

            if store.visibleConfigurations.isEmpty {
                Spacer(minLength: 20)
                Button { add() } label: {
                    VStack(spacing: 18) {
                        Image(systemName: "plus").font(.system(size: 29, weight: .medium))
                            .frame(width: 70, height: 70)
                            .background(Color.accentColor.opacity(0.07), in: RoundedRectangle(cornerRadius: 22))
                        Text("Add configuration").font(.system(size: 16, weight: .medium))
                    }
                }.accessibilityIdentifier("addConfiguration")
                Spacer(minLength: 60)
            } else {
                ScrollView {
                    LazyVStack(spacing: 12) {
                        ForEach(store.visibleConfigurations) { configuration in row(configuration) }
                    }.padding(.bottom, 16)
                }.scrollIndicators(.hidden)
            }
            Text(store.mode.caption)
                .font(.caption).foregroundStyle(muted).padding(.bottom, 12).padding(.top, 8)
        }
        .padding(.horizontal, 24).frame(maxWidth: 620).frame(maxWidth: .infinity)
        .background(Color.white)
        .sheet(isPresented: $panel.showingSubscription) { SubscriptionView(adding: panel.subscriptions.isEmpty || !panel.activationText.isEmpty) }
        .sheet(isPresented: $showingConnectionGuide) { ConnectionGuide() }
        .sheet(item: $editor) { value in
            ConfigurationEditor(store: store, configuration: value, canCaptureDNS: !vpn.tunnelIsActive,
                                isNewConfiguration: !store.configurations.contains(where: { $0.id == value.id })) { updated in
                try store.save(updated)
            }
        }
        .sheet(isPresented: $showingCaptcha) {
            LocalCaptchaView(url: URL(string: vpn.turnCaptchaURL) ?? URL(string: "http://localhost:8765/")!)
                .id(vpn.turnCaptchaID)
        }
        .sheet(isPresented: $showingAutomation) {
            SettingsEditor(store: store, runtime: runtime, autoCaptcha: store.autoCaptcha, autoRecovery: store.autoRecovery, autoConnectOnLaunch: store.autoConnectOnLaunch,
                           turnCheckInterval: store.turnCheckInterval, turnSessionCount: store.turnSessionCount, splitTunneling: store.splitTunneling,
                           amneziaSplitEnabled: store.amneziaSplitEnabled, fullTunnelMinutes: store.fullTunnelMinutes, onImport: { backup in
                connectionTask?.cancel()
                try await vpn.disconnectForImport()
                try runtime.clearPreparedConfiguration()
                try store.restore(backup)
                runtime.applyPanelDNS(store.applicationDNSServers)
                runtime.restoreSelection(store.availableConfigurations, profileID: store.selectedProfileID)
                runtime.applySplitTunneling(store.splitTunneling)
                runtime.applySplitOptions(amnezia: store.amneziaSplitEnabled, minutes: store.fullTunnelMinutes)
                runtime.applyAutomation(autoCaptcha: store.autoCaptcha, autoRecovery: store.autoRecovery, turnCheckInterval: store.turnCheckInterval, turnSessionCount: store.turnSessionCount)
                vpn.bind(store: runtime)
            }) { captcha, recovery, autoStart, interval, split, amneziaSplit, fullMinutes, sessions in
                let routingChanged = store.splitTunneling != split || store.amneziaSplitEnabled != amneziaSplit
                try store.saveSplitTunneling(split)
                store.amneziaSplitEnabled = amneziaSplit; store.fullTunnelMinutes = fullMinutes
                store.autoConnectOnLaunch = autoStart
                store.autoCaptcha = captcha; store.autoRecovery = recovery; store.turnCheckInterval = interval; store.turnSessionCount = sessions
                runtime.applySplitTunneling(split)
                runtime.applySplitOptions(amnezia: amneziaSplit, minutes: fullMinutes)
                runtime.applyAutomation(autoCaptcha: captcha, autoRecovery: recovery, turnCheckInterval: interval, turnSessionCount: sessions)
                if routingChanged && vpn.tunnelIsActive && runtime.activeProfile != nil {
                    await vpn.connect(using: runtime)
                    panel.connectionAppliedSettings()
                } else {
                    await vpn.applyAutomationSettings(using: runtime)
                }
            }
        }
        .onValueChange(of: vpn.turnCaptchaRequired) { required in
            // Native verification and its invisible browser fallback never present a sheet.
            if !required { showingCaptcha = false }
        }
        .onValueChange(of: vpn.isConnected) { connected in
            if !connected {
                pingRequestID = nil; checkingPing = false; pingUnavailable = false
            }
        }
        .task(id: pingRequestID) {
            guard pingRequestID != nil else { return }
            let latency = await vpn.refreshLatency()
            guard !Task.isCancelled else { return }
            pingUnavailable = latency == nil
            checkingPing = false
        }
        #if DEBUG
        .task {
            #if targetEnvironment(macCatalyst)
            if ProcessInfo.processInfo.arguments.contains("--storage-check") {
                var report: [String: Any] = ["group": AppGroup.id]
                do {
                    try AppGroup.verifyAccess()
                    report["phase"] = "storage-ok"
                } catch {
                    let failure = error as NSError
                    report["phase"] = "storage-failed"
                    report["error"] = failure.localizedDescription
                    if let inner = failure.userInfo[NSUnderlyingErrorKey] as? NSError {
                        report["underlyingDomain"] = inner.domain
                        report["underlyingCode"] = inner.code
                    }
                }
                if let directory = AppGroup.containerURL {
                    report["container"] = directory.path
                    let file = directory.appendingPathComponent("shared-preferences.plist")
                    if let data = try? Data(contentsOf: file) {
                        report["preferencesBytes"] = data.count
                        report["preferencesPrefix"] = String(data: data.prefix(8), encoding: .utf8) ?? "binary"
                        if let value = try? PropertyListSerialization.propertyList(from: data, format: nil) {
                            report["preferencesType"] = String(describing: type(of: value))
                        }
                    }
                }
                if let data = try? JSONSerialization.data(withJSONObject: report, options: [.sortedKeys]) {
                    FileHandle.standardOutput.write(data + Data("\n".utf8))
                }
                return
            }
            if ProcessInfo.processInfo.arguments.contains("--mac-network-check") {
                await runMacNetworkCheck()
                return
            }
            #endif
            #if !targetEnvironment(macCatalyst) && !targetEnvironment(simulator)
            if ProcessInfo.processInfo.arguments.contains("--device-existing-runtime44") {
                do {
                    try await vpn.restartPreparedAmneziaForDiagnostic()
                    await runDeviceSystemCheck()
                    let before = AppGroup.defaults.data(forKey: "diagnostic.system-check.v1")
                        .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
                    guard before?["phase"] as? String == "passed" else { return }
                    guard await vpn.schedulePreparedAmneziaSoftRebindForDiagnostic() else {
                        saveDeviceReport(["phase": "failed", "detail": "Native socket refresh was not accepted"]); return
                    }
                    try await Task.sleep(for: .seconds(8))
                    await runDeviceSystemCheck()
                    if let data = AppGroup.defaults.data(forKey: "diagnostic.system-check.v1"),
                       var after = try JSONSerialization.jsonObject(with: data) as? [String: Any] {
                        after["softRebindRequested"] = true
                        after["providerUnchanged"] = (before?["providerProcessID"] as? Int) == (after["providerProcessID"] as? Int)
                        saveDeviceReport(after)
                    }
                } catch { saveDeviceReport(["phase": "failed", "detail": error.localizedDescription]) }
                return
            }
            #endif
            if ProcessInfo.processInfo.arguments.contains("--device-amnezia-system-check") {
                await runDeviceSystemCheck()
                return
            }
            if ProcessInfo.processInfo.arguments.contains("--device-subscription-check") {
                await reportDeviceSubscriptionCheck()
                return
            }
            let amneziaCheck = ProcessInfo.processInfo.arguments.contains("--device-amnezia-background-check")
            guard amneziaCheck || ProcessInfo.processInfo.arguments.contains("--device-turn-background-check") else { return }
            let deadline = Date().addingTimeInterval(240)
            while !Task.isCancelled && Date() < deadline {
                if vpn.isConnected {
                    if amneziaCheck && runtime.activeProfile?.isAmnezia == true {
                        if await vpn.schedulePacketFlowRecoveryDiagnostic() { return }
                    } else if !amneziaCheck && vpn.turnReady {
                        if await vpn.scheduleBackgroundRecoveryDiagnostic() { return }
                    }
                }
                do { try await Task.sleep(for: .seconds(1)) } catch { return }
            }
        }
        #endif
        .alert("Action failed", isPresented: Binding(
            get: { errorMessage != nil },
            set: { if !$0 { clearErrors() } }
        )) { Button("OK") { clearErrors() } } message: { Text(errorMessage ?? "") }
        .confirmationDialog("Delete configuration?", isPresented: Binding(
            get: { pendingDelete != nil }, set: { if !$0 { pendingDelete = nil } }
        ), titleVisibility: .visible, presenting: pendingDelete) { value in
            Button("Delete", role: .destructive) {
                do { try store.remove(value) } catch { store.error = error.localizedDescription }
                pendingDelete = nil
            }
            Button("Cancel", role: .cancel) { pendingDelete = nil }
        }
    }

    #if DEBUG
    @MainActor private func reportDeviceSubscriptionCheck() async {
        let file = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent("subscription-device-report.json")
        for _ in 0..<600 {
            let subscriptions: [[String: Any]] = panel.subscriptions.map { sub in
                ["id": sub.id, "active": sub.accessAllowed(now: Int64(Date().timeIntervalSince1970)),
                 "profiles": sub.package.profiles.map { ["id": $0.id, "mode": $0.mode] }]
            }
            let report: [String: Any] = ["build": Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") ?? "",
                "subscriptions": subscriptions, "busy": panel.busy, "error": panel.error ?? "",
                "additionError": { if case .failed(let message) = panel.addition { return message }; return "" }(),
                "builtInDNSVisible": store.availableConfigurations.contains(where: \.isBuiltInDNS),
                "connected": vpn.isConnected, "status": vpn.statusTitle, "profileID": vpn.connectedProfileID ?? "",
                "updatedAt": ISO8601DateFormatter().string(from: Date())]
            if let data = try? JSONSerialization.data(withJSONObject: report) { try? data.write(to: file, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication]) }
            do { try await Task.sleep(for: .milliseconds(500)) } catch { return }
        }
    }

    @MainActor private func runDeviceSystemCheck() async {
        // Read-only diagnostic: do not reconnect or rebuild VPN preferences.
        var report: [String: Any] = ["phase": "checking", "appProcessID": getpid(),
            "build": Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") ?? ""]
        let deadline = Date().addingTimeInterval(5)
        while !vpn.isConnected && Date() < deadline {
            do { try await Task.sleep(for: .milliseconds(100)) } catch { return }
        }
        guard vpn.isConnected else { report["phase"] = "failed"; report["detail"] = "VPN is not connected"; saveDeviceReport(report); return }
        if let data = AppGroup.defaults.data(forKey: AppGroup.recoveryStatusKey),
           let recovery = try? JSONDecoder().decode(TunnelRecoverySnapshot.self, from: data) {
            report["providerProcessID"] = recovery.providerProcessID
        }
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 20; config.timeoutIntervalForResource = 25
        let session = URLSession(configuration: config)
        defer { session.invalidateAndCancel() }
        var results = [[String: Any]]()
        do {
            guard let latency = await vpn.refreshLatency() else { throw ConfigurationError("Forced-tunnel HTTPS and packet DNS did not respond") }
            report["forcedTunnelLatency"] = latency
            for raw in ["https://www.gstatic.com/generate_204", "https://www.youtube.com/", "https://speed.cloudflare.com/__down?bytes=1048576"] {
                let (data, response) = try await session.data(from: URL(string: raw)!)
                let status = (response as? HTTPURLResponse)?.statusCode ?? 0
                results.append(["host": URL(string: raw)!.host!, "status": status, "bytes": data.count])
                guard (200..<400).contains(status), !raw.contains("bytes=") || data.count >= 1_048_576 else {
                    throw ConfigurationError("System traffic check failed")
                }
            }
            report["phase"] = "passed"
        } catch { report["phase"] = "failed"; report["detail"] = error.localizedDescription }
        report["results"] = results
        saveDeviceReport(report)
    }

    private func saveDeviceReport(_ value: [String: Any]) {
        var report = value; report["updatedAt"] = ISO8601DateFormatter().string(from: Date())
        AppGroup.defaults.set(try? JSONSerialization.data(withJSONObject: report), forKey: "diagnostic.system-check.v1")
        AppGroup.defaults.synchronize()
    }
    #endif

    #if DEBUG && targetEnvironment(macCatalyst)
    @MainActor private func runMacNetworkCheck() async {
        func report(_ phase: String, _ detail: String = "", latency: Int? = nil) {
            let value: [String: Any] = ["phase": phase, "detail": detail,
                "latencyMilliseconds": latency ?? -1, "appProcessID": getpid(),
                "updatedAt": ISO8601DateFormatter().string(from: Date())]
            if let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) {
                if let directory = AppGroup.containerURL {
                    try? data.write(to: directory.appendingPathComponent("mac-network-check.json"), options: .atomic)
                }
                FileHandle.standardOutput.write(data + Data("\n".utf8))
            }
        }
        do {
            try await Task.sleep(for: .seconds(2))
            if ProcessInfo.processInfo.arguments.contains("--diagnostic-import-stdin") {
                let backup = try ApplicationBackup.decode(try FileHandle.standardInput.readToEnd() ?? Data())
                try await vpn.disconnectForImport()
                try runtime.clearPreparedConfiguration()
                try store.restore(backup)
                runtime.applySplitTunneling(store.splitTunneling)
                runtime.applyAutomation(autoCaptcha: store.autoCaptcha, autoRecovery: store.autoRecovery, turnCheckInterval: store.turnCheckInterval, turnSessionCount: store.turnSessionCount)
                report("imported", "Profiles: \(store.configurations.count)")
            }
            let mode: TunnelMode = ProcessInfo.processInfo.arguments.contains("--check-dns") ? .dns : .turn
            guard let configuration = store.configurations.first(where: { $0.mode == mode }) else {
                report("failed", "No imported profile for selected mode"); return
            }
            try await vpn.disconnectForImport()
            runtime.applyAutomation(autoCaptcha: store.autoCaptcha, autoRecovery: store.autoRecovery, turnCheckInterval: store.turnCheckInterval, turnSessionCount: store.turnSessionCount)
            try runtime.prepare(configuration)
            store.mode = mode; store.rememberSelection(configuration.id)
            report("connecting")
            await vpn.connect(using: runtime)
            let deadline = Date().addingTimeInterval(240)
            var nextReport = Date.distantPast
            while Date() < deadline {
                if Date() >= nextReport {
                    report("checking", vpn.statusTitle + " · " + vpn.recovery.detail + " · " + vpn.turnDetail)
                    nextReport = Date().addingTimeInterval(5)
                }
                if let error = vpn.lastError { report("failed", error); return }
                if vpn.isConnected, let latency = await vpn.refreshLatency() {
                    report("connected", latency: latency)
                    if ProcessInfo.processInfo.arguments.contains("--check-recovery") {
                        guard await vpn.scheduleBackgroundRecoveryDiagnostic() else {
                            report("failed", "Provider declined diagnostic drop"); return
                        }
                    }
                    return
                }
                try await Task.sleep(for: .seconds(1))
            }
            report("failed", "Timed out waiting for verified route")
        } catch { report("failed", error.localizedDescription) }
    }
    #endif

    private var statusConfiguration: SimpleConfiguration? {
        let selected = vpn.connectedProfileID ?? store.selectedProfileID
        return store.availableConfigurations.first { $0.id == selected } ?? store.visibleConfigurations.first
    }

    private var statusPanel: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                Circle().fill(vpn.isConnected ? Color.green : (vpn.tunnelIsActive ? Color.orange : muted))
                    .frame(width: 8, height: 8)
                ZStack(alignment: .leading) {
                    // Let SwiftUI reserve the longest normal status at this
                    // width, rather than pinning a height or clipping large text.
                    ForEach(["Preparing…", "Disconnected", "Connecting…", "Connected", "Disconnecting…"], id: \.self) { title in
                        Text(title).hidden().accessibilityHidden(true)
                    }
                    Text(preparing ? "Preparing…" : (vpn.turnCaptchaRequired ? (vpn.turnCaptchaNeedsUser(automatic: false) ? "VK verification required" : "Verifying VK…") : vpn.statusTitle))
                        .accessibilityIdentifier("connectionStatus")
                }
                .font(.system(size: 16, weight: .semibold)).foregroundStyle(ink)
                .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 4)
                ProgressView().controlSize(.small).frame(width: 16)
                    .opacity((vpn.tunnelIsActive || preparing) && !vpn.isConnected ? 1 : 0)
                    .accessibilityHidden(!((vpn.tunnelIsActive || preparing) && !vpn.isConnected))
                pingButton
            }
            Text(statusConfiguration?.title ?? "Select a configuration")
                .font(.caption).foregroundStyle(muted).fixedSize(horizontal: false, vertical: true)
                .accessibilityIdentifier("statusProfile")
            HStack(alignment: .top, spacing: 8) {
                metric("↓ Download", value: TrafficDisplay.speed(vpn.downloadSpeed))
                Spacer(minLength: 2)
                metric("↑ Upload", value: TrafficDisplay.speed(vpn.uploadSpeed))
                Spacer(minLength: 2)
                metric("Total", value: TrafficDisplay.bytes(Double(vpn.uploadedBytes) + Double(vpn.downloadedBytes)))
            }
            VStack(alignment: .leading, spacing: 0) {
                HStack(spacing: 8) {
                if vpn.tunnelIsActive || preparing {
                    statusAction("Disconnect", identifier: "disconnect") { stopConnection() }
                        .disabled(vpn.status == .disconnecting)
                } else {
                    statusAction("Connect", identifier: "connectSelected") {
                        if let configuration = statusConfiguration { connect(configuration) }
                    }.disabled(statusConfiguration == nil)
                }
                if let profile = statusConfiguration,
                   TemporaryFullTunnelPolicy.supported(isTURN: profile.mode == .turn, isDNS: profile.mode == .dns,
                                                       isAmnezia: profile.mode == .amnezia, amneziaSplit: store.amneziaSplitEnabled) {
                    Toggle("Всё в туннель", isOn: Binding(get: { vpn.isConnected && vpn.temporaryFullTunnel }, set: { enabled in
                        Task { await vpn.setTemporaryFullTunnel(enabled) }
                    }))
                    .font(.system(size: 13)).toggleStyle(.switch).fixedSize()
                    .disabled(!vpn.isConnected || vpn.routingSwitchPending)
                    .accessibilityIdentifier("temporaryFullTunnel")
                }
                }
                if vpn.recoveryFailed {
                    statusAction("Retry", identifier: "retryConnection") { vpn.retryRecovery(using: runtime) }
                }
                if vpn.turnCaptchaRequired {
                    statusAction("Complete VK verification", identifier: "completeVKVerification") { showingCaptcha = true }
                }
            }
            if vpn.isRecovering && vpn.recovery.attempt > 0 {
                Text("Attempt \(vpn.recovery.attempt) of \(vpn.recovery.maximumAttempts)")
                    .font(.caption).foregroundStyle(muted)
            }
        }
        .padding(.horizontal, 20).padding(.vertical, 10)
        .background(Color(red: 0.96, green: 0.97, blue: 0.985), in: RoundedRectangle(cornerRadius: 22))
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("connectionStatusCard")
    }

    private func statusAction(_ title: String, identifier: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            ZStack(alignment: .leading) {
                Text("Disconnect").hidden().accessibilityHidden(true)
                Text(title)
            }
                .font(.subheadline.weight(.semibold)).foregroundStyle(Color.accentColor).multilineTextAlignment(.leading)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain).accessibilityIdentifier(identifier)
    }

    private var pingText: String {
        guard vpn.isConnected, !checkingPing, !pingUnavailable, let latency = vpn.currentLatencyMilliseconds else { return "— ms" }
        return "\(latency) ms"
    }

    private var pingButton: some View {
        Button {
            checkingPing = true; pingUnavailable = false; pingRequestID = UUID()
        } label: {
            HStack(spacing: 5) {
                if checkingPing {
                    ProgressView().controlSize(.mini).frame(width: 12, height: 12)
                } else {
                    Image(systemName: "arrow.clockwise").font(.system(size: 11, weight: .semibold))
                }
                Text(pingText).font(.system(size: 12, weight: .medium)).monospacedDigit()
                    .lineLimit(1).minimumScaleFactor(0.75)
            }
            .frame(width: 76, height: 28)
            .foregroundStyle(vpn.isConnected ? Color.accentColor : muted)
            .background(Color.white.opacity(0.85), in: Capsule())
            // Expand the hit area without adding height to the status panel.
            .padding(.vertical, 8).contentShape(Rectangle()).padding(.vertical, -8)
        }
        .buttonStyle(.plain).disabled(!vpn.isConnected || checkingPing)
        .accessibilityLabel(checkingPing ? "Checking latency" : "Check latency")
        .accessibilityValue(pingUnavailable ? "No response" : pingText)
        .accessibilityHint("HTTP response time through the connected VPN, including connection setup")
        .help("HTTP RealDelay through VPN · DNS, TCP and TLS included when needed")
        .accessibilityIdentifier("pingConnection")
    }

    private func metric(_ label: String, value: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(label).font(.system(size: 11, weight: .medium)).foregroundStyle(muted)
            Text(value).font(.system(size: 14, weight: .semibold, design: .rounded))
                .monospacedDigit().foregroundStyle(ink).lineLimit(1).minimumScaleFactor(0.8)
        }
    }

    private var addButton: some View {
        Button { add() } label: {
            Image(systemName: "plus").font(.system(size: 18, weight: .semibold)).frame(width: 44, height: 44)
        }.accessibilityLabel("Add configuration").accessibilityIdentifier("addConfiguration")
    }

    private func add() {
        var value = SimpleConfiguration(); value.mode = store.mode
        if value.mode == .dns, let dns = store.applicationDNSTunnel {
            value.dns.domain = dns.domain; value.dns.publicKey = dns.publicKey; value.dns.resolver = dns.resolver
            value.dns.sessionCount = dns.sessionCount; value.dns.savedResolvers = dns.savedResolvers
            value.dns.autoDetectResolver = dns.autoDetectResolver; value.dns.useWiFiResolver = dns.useWiFiResolver; value.dns.wifiResolver = dns.wifiResolver
        }
        editor = value
    }

    private func row(_ value: SimpleConfiguration) -> some View {
        let active = vpn.connectedProfileID == value.id && vpn.tunnelIsActive
        return HStack(spacing: 12) {
            Button { connect(value) } label: {
                HStack(spacing: 14) {
                    Image(systemName: active ? "stop.fill" : "play.fill")
                        .font(.system(size: 15)).foregroundStyle(active ? Color.green : Color.accentColor)
                        .frame(width: 44, height: 44)
                        .background((active ? Color.green : Color.accentColor).opacity(0.08), in: RoundedRectangle(cornerRadius: 14))
                    VStack(alignment: .leading, spacing: 6) {
                        Text(value.title).font(.system(size: 16, weight: .semibold)).foregroundStyle(ink).lineLimit(1)
                        Text(active ? vpn.statusTitle : value.detail)
                            .font(.system(size: 12)).foregroundStyle(active ? .green : muted)
                    }
                    Spacer(minLength: 0)
                }.contentShape(Rectangle())
            }
            .buttonStyle(.plain).disabled(preparing)
            .accessibilityLabel("\(active ? "Disconnect" : "Connect") \(value.title)")
            .accessibilityIdentifier("connect_\(value.id)")

            if value.isBuiltInDNS {
                Image(systemName: "lock.fill").foregroundStyle(muted).frame(width: 44, height: 44)
                    .accessibilityLabel("Built-in DNS profile, cannot be edited or deleted")
                    .accessibilityIdentifier("builtInDNSLock")
            } else { Menu {
                if value.managed == nil {
                    Button("Edit", systemImage: "pencil") { editor = value }
                    Button("Delete", systemImage: "trash", role: .destructive) { pendingDelete = value }
                } else { Button("Subscription", systemImage: "person.crop.circle") { panel.showingSubscription = true } }
            } label: {
                Image(systemName: "ellipsis").font(.system(size: 20, weight: .semibold))
                    .foregroundStyle(muted).frame(width: 44, height: 44)
            }
            .disabled((active && value.managed == nil) || preparing)
            .accessibilityLabel("Settings \(value.title)").accessibilityIdentifier("settings_\(value.id)")
            }
        }
        .padding(14)
        .background(Color.white, in: RoundedRectangle(cornerRadius: 19))
        .overlay(RoundedRectangle(cornerRadius: 19).stroke(active ? Color.green.opacity(0.35) : Color.black.opacity(0.08), lineWidth: 1))
    }

    private func connect(_ value: SimpleConfiguration) {
        if vpn.connectedProfileID == value.id && vpn.tunnelIsActive { stopConnection(); return }
        guard !preparing else { return }
        preparing = true
        connectionTask = Task { @MainActor in
            #if !targetEnvironment(macCatalyst)
            let startupActivity = VPNStartupActivity()
            defer { startupActivity.finish() }
            #endif
            defer { preparing = false; connectionTask = nil }
            do {
                _ = try value.validated(forConnection: true)
                try PanelAccess.require(value.profile.panelAccess, vault: store.panelVault)
                #if !targetEnvironment(simulator)
                await vpn.load()
                try Task.checkCancellation()
                #endif
                // Stop the old provider before replacing its shared configuration.
                if vpn.tunnelIsActive {
                    vpn.disconnect()
                    let deadline = Date().addingTimeInterval(10)
                    while vpn.tunnelIsActive && Date() < deadline { try await Task.sleep(for: .milliseconds(100)) }
                    guard !vpn.tunnelIsActive else { throw ConfigurationError("The previous connection is still disconnecting. Try again in a few seconds.") }
                }
                #if targetEnvironment(simulator)
                throw ConfigurationError("Test VPN connections on an iPhone or iPad. The simulator supports adding and editing profiles.")
                #else
                var selected = value
                if selected.mode == .dns && selected.dns.autoDetectResolver {
                    let network = await SystemDNSResolver.networkSnapshot()
                    try Task.checkCancellation()
                    selected = try store.applyingDetectedDNS(to: selected, servers: network.servers, usingWiFi: network.usesWiFi)
                }
                runtime.applyAutomation(autoCaptcha: store.autoCaptcha, autoRecovery: store.autoRecovery, turnCheckInterval: store.turnCheckInterval, turnSessionCount: store.turnSessionCount)
                runtime.applySplitTunneling(store.splitTunneling)
                try runtime.prepare(selected)
                store.rememberSelection(selected.id)
                await vpn.connect(using: runtime)
                panel.connectionAppliedSettings()
                #endif
            } catch is CancellationError {
                return
            } catch { store.error = error.localizedDescription }
        }
    }

    private func stopConnection() { connectionTask?.cancel(); vpn.disconnect() }

    private func clearErrors() { panel.error = nil; store.error = nil; vpn.lastError = nil; vpn.connectionDropMessage = nil }
}

#if !targetEnvironment(macCatalyst)
/// Keep the host alive only while it reads DNS and hands startup to iOS. The
/// packet extension handles the active connection after this lease ends.
@MainActor private final class VPNStartupActivity {
    private var identifier = UIBackgroundTaskIdentifier.invalid

    init() {
        identifier = UIApplication.shared.beginBackgroundTask(withName: "Start TnDtun VPN") { [weak self] in
            self?.finish()
        }
    }

    func finish() {
        guard identifier != .invalid else { return }
        let current = identifier
        identifier = .invalid
        UIApplication.shared.endBackgroundTask(current)
    }
}
#endif
