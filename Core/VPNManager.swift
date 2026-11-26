import Foundation
import Combine
import SwiftyXrayKit
@preconcurrency import NetworkExtension

@MainActor
final class VPNManager: ObservableObject {
    @Published private(set) var recovery = TunnelRecoverySnapshot()
    @Published private(set) var connectedProfileID: String?
    @Published private(set) var status: NEVPNStatus = .invalid
    @Published private(set) var uploadedBytes: UInt64 = 0
    @Published private(set) var downloadedBytes: UInt64 = 0
    @Published private(set) var turnReady = false
    @Published private(set) var temporaryFullTunnel = false
    @Published private(set) var routingSwitchPending = false
    @Published private(set) var turnTransport = ""
    @Published private(set) var turnConnectedStreams = 0
    @Published private(set) var turnCaptchaRequired = false
    @Published private(set) var turnCaptchaID: UInt64 = 0
    @Published private(set) var turnCaptchaAgeMilliseconds: Int64 = 0
    @Published private(set) var turnCaptchaURL = "http://localhost:8765/"
    @Published private(set) var turnDetail = ""
    // Header RealDelay belongs only to the manual button, never to health checks.
    @Published private(set) var currentLatencyMilliseconds: Int?
    @Published private(set) var connectionDetail = "VPN is disconnected"
    @Published private(set) var isTryingFastest = false
    @Published var lastError: String?
    @Published var connectionDropMessage: String?

    @Published private(set) var uploadSpeed: Double = 0
    @Published private(set) var downloadSpeed: Double = 0
    private var lastStatisticsAt: Date?
    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?
    private var statisticsTask: Task<Void, Never>?
    private var connectionAttemptID: UUID?
    private var commandID = UUID()
    private var preferencesTask: Task<Void, Error>?
    private var startIsPending = false
    private var launchIntent = AppLaunchIntent()
    private var preferencesLoaded = false
    private weak var reconnectStore: AppStore?
    private var connectionWasActive = false
    private var expectedShutdown = true

    #if DEBUG
    // Offline UI fixtures never create a system VPN or invoke a transport.
    private var interfaceFixture: String? {
        guard ProcessInfo.processInfo.arguments.contains("--ui-testing"),
              let value = ProcessInfo.processInfo.environment["TNDTUN_UI_CONNECTION_STATE"],
              ["disconnected", "connecting", "captcha", "connected", "disconnecting", "retry"].contains(value) else { return nil }
        return value
    }
    #endif

    init() {
        uploadedBytes = (AppGroup.defaults.object(forKey: AppGroup.uploadedBytesKey) as? NSNumber)?.uint64Value ?? 0
        downloadedBytes = (AppGroup.defaults.object(forKey: AppGroup.downloadedBytesKey) as? NSNumber)?.uint64Value ?? 0
        #if DEBUG
        if let fixture = interfaceFixture {
            status = fixture == "disconnected" ? .disconnected : (fixture == "connected" ? .connected : (fixture == "disconnecting" ? .disconnecting : (fixture == "retry" ? .reasserting : .connecting)))
            recovery.phase = fixture == "captcha" ? .captcha : (fixture == "retry" ? .failed : (fixture == "connected" ? .connected : .disconnected))
            recovery.detail = fixture == "retry" ? "Connection failed.\nPlease retry." : "VK verification required"
            turnCaptchaRequired = fixture == "captcha"
            turnCaptchaAgeMilliseconds = Int64(ProcessInfo.processInfo.environment["TNDTUN_UI_CHALLENGE_AGE_MS"] ?? "") ?? 0
            turnCaptchaURL = "" // No hidden browser is needed for a static layout check.
            turnReady = fixture == "connected"
            connectedProfileID = fixture == "disconnected" ? nil : ProcessInfo.processInfo.environment["TNDTUN_UI_PROFILE_ID"]
            return
        }
        #endif
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            guard let connection = notification.object as? NEVPNConnection else { return }
            Task { @MainActor in
                guard let self, self.manager?.connection === connection else { return }
                self.status = connection.status
                self.updateStatisticsLoop()
                if connection.status == .connected {
                    self.connectionWasActive = true
                    self.expectedShutdown = false
                    self.connectionDropMessage = nil
                    self.currentLatencyMilliseconds = nil
                }
                if self.isTryingFastest == false {
                    if connection.status == .connected {
                        self.startIsPending = false
                        self.connectionDetail = "Connected"
                    }
                    if connection.status == .disconnected || connection.status == .invalid {
                        let unexpected = ConnectionDropPolicy.isUnexpected(
                            connectionWasActive: self.connectionWasActive,
                            shutdownExpected: self.expectedShutdown
                        )
                        self.connectionWasActive = false
                        self.currentLatencyMilliseconds = nil
                        self.connectionDetail = "VPN is disconnected"
                        if unexpected {
                            self.handleUnexpectedDrop(connection)
                        } else if self.startIsPending == true {
                            Task { @MainActor [weak self, connection] in
                                try? await Task.sleep(for: .seconds(1))
                                guard let self,
                                      self.startIsPending,
                                      [.disconnected, .invalid].contains(connection.status) else { return }
                                self.startIsPending = false
                                self.reportDisconnectError(connection)
                            }
                        }
                    }
                }
            }
        }
        Task { await load() }
    }

    deinit {
        if let statusObserver { NotificationCenter.default.removeObserver(statusObserver) }
        statisticsTask?.cancel()
    }

    var isRecovering: Bool {
        [.connected, .reasserting].contains(status) && recovery.phase.isRecovering
    }
    var recoveryFailed: Bool { status == .reasserting && recovery.phase == .failed }
    var tunnelIsActive: Bool { [.connecting, .connected, .reasserting, .disconnecting].contains(status) || startIsPending }
    var isConnected: Bool { status == .connected && !recovery.phase.isRecovering && recovery.phase != .failed }
    var isBusy: Bool { !isRecovering && (startIsPending || isTryingFastest || [.connecting, .disconnecting].contains(status)) }

    var statusTitle: String {
        if isRecovering || recoveryFailed { return recovery.detail }
        switch status {
        case .connected: return "Connected"
        case .connecting: return "Connecting…"
        case .disconnecting: return "Disconnecting…"
        case .reasserting: return "Reconnecting…"
        case .invalid: return "VPN is not configured"
        default: return "Disconnected"
        }
    }

    func bind(store: AppStore) {
        reconnectStore = store
        consumeNotificationAction(using: store)
    }

    func load() async {
        #if DEBUG
        guard interfaceFixture == nil else { return }
        #endif
        let token = commandID
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            guard commandID == token else { return }
            let owned = managers.filter {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == AppGroup.tunnelBundleIdentifier
            }
            manager = owned.first {
                [.connecting, .connected, .reasserting, .disconnecting].contains($0.connection.status)
            } ?? owned.first { !Self.isLegacyTelemost($0) } ?? owned.first
            preferencesLoaded = true
            status = manager?.connection.status ?? .disconnected
            connectionWasActive = status == .connected
            expectedShutdown = status != .connected
            connectedProfileID = (manager?.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["profileId"] as? String
            updateStatisticsLoop()
            if let existing = manager,
               !Self.isLegacyTelemost(existing),
               existing.localizedDescription != "TnDtun" ||
                (!Self.automationPolicy(for: existing).isTURNProxy &&
                 (existing.isOnDemandEnabled || !(existing.onDemandRules ?? []).isEmpty)) {
                let previous = preferencesTask
                let rename = Task { @MainActor in
                    _ = try? await previous?.value
                    guard self.commandID == token else { return }
                    existing.localizedDescription = "TnDtun"
                    if !Self.automationPolicy(for: existing).isTURNProxy {
                        existing.isOnDemandEnabled = false
                        existing.onDemandRules = []
                    }
                    try await existing.saveToPreferences()
                }
                preferencesTask = rename
                do { try await rename.value }
                catch {
                    if commandID == token, !Self.automationPolicy(for: existing).isTURNProxy {
                        lastError = "Automatic VPN startup could not be disabled. Try disconnecting again."
                    }
                }
            }
        } catch {
            #if targetEnvironment(simulator)
            status = .disconnected
            return
            #else
            lastError = error.localizedDescription
            status = .invalid
            #endif
        }
    }

    /// One attempt per app process, after local settings/subscriptions and OS
    /// preferences are loaded. Never prompts for permission or replaces a VPN.
    func connectOnLaunchIfNeeded(store: SimpleStore, runtime: AppStore) async {
        guard launchIntent.claim() else { return }
        guard store.autoConnectOnLaunch, store.error == nil, preferencesLoaded,
              manager?.isEnabled == true, !tunnelIsActive,
              let id = store.selectedProfileID,
              var selected = store.availableConfigurations.first(where: { $0.id == id }) else { return }
        let token = commandID
        do {
            _ = try selected.validated(forConnection: true)
            try PanelAccess.require(selected.profile.panelAccess, vault: store.panelVault)
            if selected.mode == .dns && selected.dns.autoDetectResolver {
                let network = await SystemDNSResolver.networkSnapshot()
                guard commandID == token, !Task.isCancelled, !tunnelIsActive,
                      store.autoConnectOnLaunch, store.selectedProfileID == id else { return }
                selected = try store.applyingDetectedDNS(to: selected, servers: network.servers, usingWiFi: network.usesWiFi)
            }
            guard commandID == token, !Task.isCancelled, !tunnelIsActive,
                  store.autoConnectOnLaunch, store.selectedProfileID == id,
                  store.availableConfigurations.contains(where: { $0.id == id }) else { return }
            runtime.applyAutomation(autoCaptcha: store.autoCaptcha, autoRecovery: store.autoRecovery,
                                    turnCheckInterval: store.turnCheckInterval, turnSessionCount: store.turnSessionCount)
            runtime.applySplitTunneling(from: store)
            try runtime.prepare(selected)
            await connect(using: runtime)
        } catch is CancellationError { return }
        catch { connectionDetail = "Auto-connect skipped: " + error.localizedDescription }
    }

    func connect(using store: AppStore) async {
        launchIntent.cancel()
        reconnectStore = store
        let token = UUID(); commandID = token
        cancelFallback()
        startIsPending = true
        await ProfilePinger.cancelAll()
        guard commandID == token else { return }
        if manager == nil { await load() }
        guard commandID == token else { return }
        guard let profile = store.activeProfile else {
            startIsPending = false
            lastError = "Import and select a VPN profile first."
            return
        }
        startIsPending = true
        guard await stopCurrentTunnelIfNeeded(token: token), commandID == token else { return }
        let result = await start(profile: profile, using: store, token: token)
        guard commandID == token else { return }
        if case .failure(let message) = result { startIsPending = false; lastError = message }
    }

    func connectFastest(using store: AppStore) async {
        launchIntent.cancel()
        reconnectStore = store
        guard var plan = ConnectionFallbackPlan.fastest(
            store.profiles,
            excludingVKTurn: store.turnSettings.provider == .vk
        ) else {
            lastError = store.profiles.contains(where: \.isTURN)
                ? "Connect to VK TURN manually using the play button on a profile."
                : "Import a VPN profile first."
            return
        }
        cancelFallback()
        let attemptID = UUID(); commandID = attemptID
        connectionAttemptID = attemptID
        startIsPending = true
        await ProfilePinger.cancelAll()
        guard commandID == attemptID else { return }
        if manager == nil { await load() }
        guard commandID == attemptID else { return }
        startIsPending = true
        guard await stopCurrentTunnelIfNeeded(token: attemptID), commandID == attemptID else { return }
        isTryingFastest = true
        lastError = nil

        while connectionAttemptID == attemptID {
            guard let profile = store.profiles.first(where: { $0.id == plan.current.profileID }) else {
                if plan.advance() == nil { break }
                continue
            }
            store.select(profile)
            connectionDetail = "Attempt \(plan.attemptNumber) of \(plan.count) · \(profile.name)"

            let startResult = await start(profile: profile, using: store, token: attemptID)
            guard connectionAttemptID == attemptID else { return }

            var succeeded = false
            switch startResult {
            case .success:
                connectionDetail = "Checking route · \(profile.name)"
                if await waitForStatus(.connected, timeout: profile.isTURN ? 300 : 20, token: attemptID), connectionAttemptID == attemptID {
                    try? await Task.sleep(for: .milliseconds(1_200))
                    guard connectionAttemptID == attemptID else { return }
                    if let latency = await measureConnectivity(), connectionAttemptID == attemptID {
                        recordLatency(latency, for: profile.id, in: store)
                        succeeded = true
                    }
                }
            case .cancelled: return
            case .failure(let message):
                RuntimeLog.write("Connection fallback: \(profile.name) failed: \(message)")
            }

            guard connectionAttemptID == attemptID else { return }
            if succeeded {
                mark(profileID: profile.id, error: nil, in: store)
                connectionAttemptID = nil
                isTryingFastest = false
                startIsPending = false
                connectionDetail = "Connected · \(profile.name)"
                RuntimeLog.write("Fastest connection selected \(profile.name)")
                return
            }

            mark(profileID: profile.id, error: "Connectivity check failed", in: store)
            connectionDetail = "\(profile.name) is unavailable · switching"
            guard await stopCurrentTunnelIfNeeded(token: attemptID), commandID == attemptID else { return }

            if plan.advance() == nil { break }
        }

        guard connectionAttemptID == attemptID else { return }
        connectionAttemptID = nil
        isTryingFastest = false
        startIsPending = false
        connectionDetail = "All profiles are unavailable"
        lastError = "No profiles could connect. Run Ping all or update your subscription."
    }

    private func start(profile: VPNProfile, using store: AppStore, token: UUID) async -> TunnelStartResult {
        guard commandID == token, !Task.isCancelled else { return .cancelled }
        if let error = profile.connectionValidationError { return .failure(error) }
        do { try PanelAccess.require(profile.panelAccess); try AppGroup.verifyAccess() }
        catch { return .failure(error.localizedDescription) }
        guard store.writeActiveConfiguration(profile: profile) else {
            return .failure("The active configuration could not be created.")
        }
        if profile.isManagedDNS {
            do { _ = try ManagedDNSStore.load().validated() }
            catch { return .failure(error.localizedDescription) }
        }
        if profile.isDNS && !RecoveryTransportStore.dnsConfigured {
            return .failure("The DNS tunnel is unavailable. Update your subscription when internet access is available.")
        }
        if profile.isTURN && !profile.isTelemost && !profile.isDNS && !profile.isManagedDNS &&
            !RecoveryTransportStore.enabled && !store.turnSettings.isConfigured {
            return .failure("Configure the TURN transport first.")
        }
        lastError = nil
        connectionDetail = "Connecting · \(profile.name)"
        do {
            let current = manager ?? makeManager()
            let previous = preferencesTask
            let appSettings = store.settings
            let turnSettings = store.turnSettings
            let task = Task { @MainActor in
                _ = try? await previous?.value
                guard self.commandID == token, !Task.isCancelled else { throw CancellationError() }
                Self.configure(current, profile: profile, settings: appSettings, turnSettings: turnSettings)
                try await current.saveToPreferences()
                try await current.loadFromPreferences()
            }
            preferencesTask = task
            try await task.value
            guard commandID == token, !Task.isCancelled else { return .cancelled }
            manager = current
            connectedProfileID = profile.id
            recovery = TunnelRecoverySnapshot(profileID: profile.id)
            startIsPending = true
            connectionWasActive = false
            expectedShutdown = false
            try current.connection.startVPNTunnel(options: ["profileId": profile.id as NSString])
            RuntimeLog.write("Connecting with profile \(profile.name)")
            return .success
        } catch {
            guard commandID == token, !Task.isCancelled else { return .cancelled }
            startIsPending = false
            expectedShutdown = true
            let message = friendlyError(error)
            RuntimeLog.write("VPN start failed: \(error.localizedDescription)")
            return .failure(message)
        }
    }

    func disconnect() {
        launchIntent.cancel()
        commandID = UUID()
        let token = commandID
        cancelFallback()
        expectedShutdown = true
        connectionWasActive = false
        startIsPending = false
        manager?.connection.stopVPNTunnel()
        // Disable persisted on-demand rules too, otherwise iOS can restart the
        // extension immediately after the user's explicit stop.
        if let manager {
            manager.isOnDemandEnabled = false
            manager.onDemandRules = []
            let previous = preferencesTask
            let task = Task { @MainActor in
                _ = try? await previous?.value
                guard self.commandID == token else { return }
                manager.isOnDemandEnabled = false
                manager.onDemandRules = []
                try await manager.saveToPreferences()
                guard self.commandID == token else { return }
                manager.connection.stopVPNTunnel()
            }
            preferencesTask = task
            Task { [weak self] in
                do { try await task.value }
                catch { if self?.commandID == token { self?.lastError = "Automatic VPN startup could not be disabled. Try disconnecting again." } }
            }
        }
        recovery = TunnelRecoverySnapshot()
        connectedProfileID = nil
        currentLatencyMilliseconds = nil
        turnReady = false; turnCaptchaRequired = false
        connectionDetail = "VPN is disconnected"
        RuntimeLog.write("Disconnect requested")
    }

    func disconnectForImport() async throws {
        disconnect()
        let token = commandID
        try await preferencesTask?.value
        let deadline = Date().addingTimeInterval(15)
        status = manager?.connection.status ?? status
        while tunnelIsActive && Date() < deadline {
            guard commandID == token else { throw CancellationError() }
            try await Task.sleep(for: .milliseconds(100))
            status = manager?.connection.status ?? status
        }
        guard commandID == token else { throw CancellationError() }
        guard !tunnelIsActive else {
            throw ConfigurationError("VPN is still disconnecting. Try importing again in a few seconds.")
        }
    }

    func toggle(using store: AppStore) async {
        if isConnected || isBusy || isRecovering || recoveryFailed { disconnect() }
        else { await connect(using: store) }
    }

    func toggleFastest(using store: AppStore) async {
        if isConnected || isBusy || isRecovering || recoveryFailed { disconnect() }
        else { await connectFastest(using: store) }
    }

    func showConnectionDetail(_ message: String) {
        connectionDetail = message
    }

    func measureConnectivity() async -> Int? {
        await measureProviderLatency(command: "probe")
    }

    private func measureProviderLatency(command: String) async -> Int? {
        let token = commandID
        guard isConnected, let expectedProfile = connectedProfileID,
              let response = await providerMessage(command),
              let result = try? JSONSerialization.jsonObject(with: response) as? [String: Any],
              result["profileID"] as? String == expectedProfile,
              !Task.isCancelled, commandID == token, isConnected,
              connectedProfileID == expectedProfile,
              let latency = result["latency"] as? Int, latency > 0 else { return nil }
        return latency
    }

    func refreshLatency() async -> Int? {
        let token = commandID
        currentLatencyMilliseconds = nil
        let latency = await measureProviderLatency(command: "latency")
        guard !Task.isCancelled, commandID == token, isConnected else { return nil }
        currentLatencyMilliseconds = latency
        return latency
    }

    #if DEBUG
    /// Restarts only the already configured physical-device Amnezia session.
    /// Does not prepare a profile or write VPN preferences/runtime credentials.
    func restartPreparedAmneziaForDiagnostic() async throws {
        #if targetEnvironment(macCatalyst) || targetEnvironment(simulator)
        throw ConfigurationError("This diagnostic requires the authorized physical iPad.")
        #else
        let previousCommand = commandID
        let saved = try await NETunnelProviderManager.loadAllFromPreferences()
        guard commandID == previousCommand, !Task.isCancelled else { throw CancellationError() }
        guard let prepared = saved.first(where: {
            let value = $0.protocolConfiguration as? NETunnelProviderProtocol
            return value?.providerBundleIdentifier == AppGroup.tunnelBundleIdentifier &&
                (value?.providerConfiguration?["isAmnezia"] as? NSNumber)?.boolValue == true
        }), prepared.isEnabled,
              let session = prepared.connection as? NETunnelProviderSession else {
            throw ConfigurationError("An enabled, prepared Amnezia VPN is required.")
        }
        guard !prepared.isOnDemandEnabled else {
            throw ConfigurationError("The prepared Amnezia VPN still has automatic on-demand startup enabled.")
        }
        func activeConfiguration() -> String? {
            AppGroup.activeConfigURL.flatMap { try? String(contentsOf: $0, encoding: .utf8) }
                ?? AppGroup.defaults.string(forKey: AppGroup.activeConfigKey)
        }
        guard let raw = activeConfiguration(), !raw.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              (try? JSONSerialization.jsonObject(with: Data(raw.utf8))) is [String: Any] else {
            throw ConfigurationError("The prepared Amnezia runtime configuration is missing or invalid.")
        }
        let token = UUID(); commandID = token
        launchIntent.cancel(); cancelFallback()
        manager = prepared
        connectedProfileID = (prepared.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["profileId"] as? String
        expectedShutdown = true; connectionWasActive = false; startIsPending = false
        lastError = nil; currentLatencyMilliseconds = nil
        do {
            session.stopVPNTunnel()
            let stopDeadline = Date().addingTimeInterval(15)
            while session.status != .disconnected {
                guard commandID == token, !Task.isCancelled else { throw CancellationError() }
                guard session.status != .invalid, Date() < stopDeadline else {
                    throw ConfigurationError("The prepared Amnezia VPN did not stop before the diagnostic deadline.")
                }
                try await Task.sleep(for: .milliseconds(100))
            }
            guard commandID == token, !Task.isCancelled else { throw CancellationError() }
            guard activeConfiguration() == raw else {
                throw ConfigurationError("The prepared runtime changed; diagnostic restart was cancelled.")
            }
            expectedShutdown = false; startIsPending = true
            connectionDetail = "Starting the prepared Amnezia VPN"
            try session.startVPNTunnel()
            let startDeadline = Date().addingTimeInterval(90)
            while session.status != .connected {
                guard commandID == token, !Task.isCancelled else { throw CancellationError() }
                guard session.status != .invalid, Date() < startDeadline else {
                    throw ConfigurationError("The prepared Amnezia VPN did not connect before the diagnostic deadline.")
                }
                try await Task.sleep(for: .milliseconds(200))
            }
            guard commandID == token, !Task.isCancelled else { throw CancellationError() }
            status = session.status; startIsPending = false; connectionWasActive = true
            updateStatisticsLoop()
        } catch {
            if commandID == token {
                startIsPending = false; status = session.status
                expectedShutdown = session.status != .connected
                lastError = error.localizedDescription
            }
            throw error
        }
        #endif
    }

    func schedulePreparedAmneziaSoftRebindForDiagnostic() async -> Bool {
        #if targetEnvironment(macCatalyst) || targetEnvironment(simulator)
        return false
        #else
        return await providerMessage("diagnosticAmneziaSoftRebindAfterDelay") != nil
        #endif
    }

    func scheduleBackgroundRecoveryDiagnostic() async -> Bool {
        await providerMessage("diagnosticTransportDropAfterDelay") != nil
    }
    func schedulePacketFlowRecoveryDiagnostic() async -> Bool {
        await providerMessage("diagnosticPacketFlowDropAfterDelay") != nil
    }
    #endif

    func retryRecovery(using store: AppStore) {
        connectionDropMessage = nil
        let token = commandID
        let profileID = store.activeProfileId
        Task {
            guard commandID == token, store.activeProfileId == profileID, !Task.isCancelled else { return }
            if store.activeProfile.map({ TunnelAutomationPolicy(profile: $0).isTURNProxy }) == true,
               [.connected, .reasserting].contains(status) {
                let response = await providerMessage("retry")
                guard commandID == token, store.activeProfileId == profileID, !Task.isCancelled else { return }
                if response != nil { return }
            }
            // Amnezia/DNS reconnect is one explicit Connect, not a background
            // retry loop. It also refreshes the system routes and DNS.
            guard commandID == token, store.activeProfileId == profileID, !Task.isCancelled else { return }
            await connect(using: store)
        }
    }

    func applyRecoverySettings() async {
        _ = await providerMessage("settingsChanged")
    }

    func setTemporaryFullTunnel(_ enabled: Bool) async {
        guard isConnected, !routingSwitchPending else { return }
        let token = commandID
        routingSwitchPending = true
        let response = await providerMessage(enabled ? "fullTunnelOn" : "fullTunnelOff")
        guard commandID == token else { routingSwitchPending = false; return }
        if let response, let state = try? JSONDecoder().decode(TemporaryFullTunnelState.self, from: response),
           state.profileID == connectedProfileID {
            temporaryFullTunnel = state.enabled
            routingSwitchPending = state.pending
        } else { routingSwitchPending = false }
    }

    func applyAutomationSettings(using store: AppStore) async {
        let token = commandID
        if let manager {
            let previous = preferencesTask
            let enabled = tunnelIsActive && Self.automationPolicy(for: manager).onDemandEnabled(store.settings)
            let task = Task { @MainActor in
                _ = try? await previous?.value
                guard self.commandID == token else { return }
                manager.isOnDemandEnabled = enabled
                manager.onDemandRules = enabled ? [NEOnDemandRuleConnect()] : []
                try await manager.saveToPreferences()
            }
            preferencesTask = task
            do { try await task.value }
            catch { if commandID == token { lastError = friendlyError(error) } }
        }
        guard commandID == token else { return }
        await applyRecoverySettings()
    }

    func consumeNotificationAction(using store: AppStore) {
        guard AppGroup.defaults.string(forKey: AppGroup.recoveryActionKey) == ConnectionNotifications.retryAction else { return }
        AppGroup.defaults.removeObject(forKey: AppGroup.recoveryActionKey)
        retryRecovery(using: store)
    }

    private func providerMessage(_ value: String) async -> Data? {
        guard let session = manager?.connection as? NETunnelProviderSession else { return nil }
        return await withCheckedContinuation { continuation in
            let reply = ProviderReply(continuation)
            do {
                try session.sendProviderMessage(Data(value.utf8)) { reply.finish($0) }
                let timeout = value == "latency" ? HTTPProbeRequest.realDelayTimeout + 2
                    : (value == "probe" ? 4 * ConnectionDropPolicy.probeTimeout + 3 : 18)
                DispatchQueue.main.asyncAfter(deadline: .now() + timeout) { reply.finish(nil) }
            } catch { reply.finish(nil) }
        }
    }

    private func fetchRecoveryStatus() async {
        let token = commandID
        let data = await providerMessage("recoveryStatus") ?? AppGroup.defaults.data(forKey: AppGroup.recoveryStatusKey)
        guard !Task.isCancelled, commandID == token, [.connecting, .connected, .reasserting].contains(status) else { return }
        guard let data, let latest = try? JSONDecoder().decode(TunnelRecoverySnapshot.self, from: data),
              latest.profileID == connectedProfileID else { return }
        recovery = latest
        if let data = AppGroup.defaults.data(forKey: TemporaryFullTunnelPolicy.stateKey),
           let state = try? JSONDecoder().decode(TemporaryFullTunnelState.self, from: data), state.profileID == connectedProfileID {
            temporaryFullTunnel = state.enabled; routingSwitchPending = state.pending
        } else { temporaryFullTunnel = false; routingSwitchPending = false }
        if latest.phase.isRecovering || latest.phase == .failed { connectionDetail = latest.detail }
        if latest.phase != .connected { currentLatencyMilliseconds = nil }
        if latest.phase == .connected, let latency = latest.latencyMilliseconds,
           let store = reconnectStore {
            recordLatency(latency, for: latest.profileID, in: store)
        }
    }

    func recordLatency(_ latency: Int, for profileID: String, in store: AppStore) {
        guard let index = store.profiles.firstIndex(where: { $0.id == profileID }) else { return }
        guard store.profiles[index].latencyMilliseconds != latency || store.profiles[index].lastError != nil else { return }
        store.profiles[index].latencyMilliseconds = latency
        store.profiles[index].lastError = nil
        store.save()
    }

    func reconnectNow(using store: AppStore) { retryRecovery(using: store) }

    private func makeManager() -> NETunnelProviderManager {
        let value = NETunnelProviderManager()
        value.localizedDescription = "TnDtun"
        value.isEnabled = true
        return value
    }

    private func stopCurrentTunnelIfNeeded(token: UUID) async -> Bool {
        guard commandID == token, !Task.isCancelled else { return false }
        guard let manager else { return true }
        // Persist removal before stopping TURN, otherwise its old on-demand
        // rules can relaunch it while the next Amnezia/DNS profile is prepared.
        if manager.isOnDemandEnabled || !(manager.onDemandRules ?? []).isEmpty {
            let previous = preferencesTask
            let disable = Task { @MainActor in
                _ = try? await previous?.value
                guard self.commandID == token, !Task.isCancelled else { throw CancellationError() }
                manager.isOnDemandEnabled = false
                manager.onDemandRules = []
                try await manager.saveToPreferences()
            }
            preferencesTask = disable
            do { try await disable.value }
            catch {
                guard commandID == token else { return false }
                startIsPending = false
                lastError = friendlyError(error)
                return false
            }
        }
        guard commandID == token, !Task.isCancelled else { return false }
        let connection = manager.connection
        guard ![.disconnected, .invalid].contains(connection.status) else { return true }
        expectedShutdown = true
        connectionWasActive = false
        startIsPending = false
        connection.stopVPNTunnel()
        let stopped = await waitForStatus(.disconnected, timeout: 10, token: token)
        guard commandID == token, !Task.isCancelled else { return false }
        if !stopped {
            cancelFallback()
            lastError = "The previous VPN is still stopping. Connect again once it has stopped."
            return false
        }
        startIsPending = true
        return true
    }

    private func waitForStatus(_ expected: NEVPNStatus, timeout: TimeInterval, token: UUID) async -> Bool {
        let startedAt = Date()
        let deadline = Date().addingTimeInterval(timeout)
        var observedTransition = false
        while Date() < deadline {
            guard commandID == token, !Task.isCancelled else { return false }
            let current = manager?.connection.status ?? status
            status = current
            if current == expected || (expected == .disconnected && current == .invalid) { return true }
            if expected == .connected {
                if [.connecting, .reasserting, .disconnecting].contains(current) {
                    observedTransition = true
                } else if [.disconnected, .invalid].contains(current),
                          observedTransition || Date().timeIntervalSince(startedAt) >= 2 {
                    return false
                }
            }
            try? await Task.sleep(for: .milliseconds(100))
        }
        return false
    }

    private func mark(profileID: String, error: String?, in store: AppStore) {
        guard let index = store.profiles.firstIndex(where: { $0.id == profileID }) else { return }
        store.profiles[index].lastError = error
        if error != nil { store.profiles[index].latencyMilliseconds = nil }
        store.save()
    }

    private func handleUnexpectedDrop(_ connection: NEVPNConnection) {
        expectedShutdown = true
        let fallback = "The active VPN process stopped unexpectedly."
        connectionDropMessage = fallback
        RuntimeLog.write("VPN connection dropped unexpectedly")
        connection.fetchLastDisconnectError { [weak self, weak connection] error in
            Task { @MainActor in
                guard let self, connection != nil else { return }
                if let message = error?.localizedDescription, !message.isEmpty {
                    self.connectionDropMessage = message
                    RuntimeLog.write("VPN drop reason: \(message)")
                }
            }
        }
        // Recovery of live transports is owned by PacketTunnelProvider. If iOS terminates
        // the extension itself, the app cannot execute while suspended; on-demand rules
        // or an explicit reconnect are needed to launch a new provider process.
    }

    private func cancelFallback() {
        connectionAttemptID = nil
        isTryingFastest = false
    }

    static func configure(
        _ value: NETunnelProviderManager,
        profile: VPNProfile,
        settings: AppSettings,
        turnSettings: TURNSettings
    ) {
        let configuration = (value.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
        configuration.providerBundleIdentifier = AppGroup.tunnelBundleIdentifier
        if profile.isTelemost {
            configuration.serverAddress = "Telemost"
        } else {
            configuration.serverAddress = (profile.isDNS || profile.isManagedDNS) ? "DNS tunnel" : (profile.isTURN ? turnSettings.peer : profile.address)
        }
        configuration.disconnectOnSleep = false
        configuration.providerConfiguration = [
            "profileId": profile.id,
            "isTURN": profile.isTURN,
            "isDNS": profile.isDNS,
            "isManagedDNS": profile.isManagedDNS,
            "isAmnezia": profile.isAmnezia,
            "isTelemost": profile.isTelemost,
            "mtu": profile.isTURN ? 1280 : settings.vpnMTU,
        ]
        if let grant = profile.panelAccess {
            configuration.providerConfiguration?["panelAccess"] = try? JSONEncoder().encode(grant)
            configuration.providerConfiguration?["isPanelManaged"] = true
        }
        value.protocolConfiguration = configuration
        value.localizedDescription = "TnDtun"
        value.isEnabled = true
        value.isOnDemandEnabled = TunnelAutomationPolicy(profile: profile).onDemandEnabled(settings)
        value.onDemandRules = value.isOnDemandEnabled ? [NEOnDemandRuleConnect()] : []
    }

    static func automationPolicy(for manager: NETunnelProviderManager) -> TunnelAutomationPolicy {
        let values = (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration ?? [:]
        return TunnelAutomationPolicy(isTURN: values["isTURN"] as? Bool ?? false,
                                      isDNS: values["isDNS"] as? Bool ?? false,
                                      isManagedDNS: values["isManagedDNS"] as? Bool ?? false,
                                      isAmnezia: values["isAmnezia"] as? Bool ?? false)
    }

    private static func isLegacyTelemost(_ manager: NETunnelProviderManager) -> Bool {
        let values = (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration ?? [:]
        return values["profileId"] as? String == RecoveryTransportStore.legacyTelemostProfileID &&
            values["isTelemost"] as? Bool != true
    }

    private func updateStatisticsLoop() {
        statisticsTask?.cancel()
        uploadSpeed = 0; downloadSpeed = 0; lastStatisticsAt = nil
        guard [.connecting, .connected, .reasserting].contains(status) else { return }
        statisticsTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.fetchRecoveryStatus()
                guard !Task.isCancelled else { return }
                if self?.isConnected == true { await self?.fetchStatistics() }
                guard !Task.isCancelled else { return }
                await self?.fetchTURNStatus()
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    private func fetchStatistics() async {
        let token = commandID
        guard let response = await providerMessage("stats"),
              !Task.isCancelled, commandID == token, isConnected,
              let json = try? JSONSerialization.jsonObject(with: response) as? [String: NSNumber] else { return }
        uploadedBytes = json["uploaded"]?.uint64Value ?? uploadedBytes
        downloadedBytes = json["downloaded"]?.uint64Value ?? downloadedBytes
        uploadSpeed = json["uploadSpeed"]?.doubleValue ?? 0
        downloadSpeed = json["downloadSpeed"]?.doubleValue ?? 0
    }

    private func fetchTURNStatus() async {
        let token = commandID
        if let sharedStatus = AppGroup.defaults.data(forKey: AppGroup.turnStatusKey) {
            applyTURNStatus(sharedStatus)
        }
        guard let response = await providerMessage("turnStatus"),
              !Task.isCancelled, commandID == token else { return }
        applyTURNStatus(response)
    }

    func applyTURNStatus(_ data: Data) {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }
        turnReady = json["ready"] as? Bool ?? false
        turnTransport = json["transport"] as? String ?? ""
        turnConnectedStreams = json["connected_streams"] as? Int ?? 0
        // Extra relay lanes may request manual verification while existing lanes
        // still carry traffic. Only surface a challenge that blocks readiness.
        turnCaptchaRequired = (json["captcha_required"] as? Bool ?? false) &&
            (!turnReady || json["captcha_blocks_route"] as? Bool == true)
        turnCaptchaID = (json["captcha_id"] as? NSNumber)?.uint64Value ?? 0
        turnCaptchaAgeMilliseconds = (json["captcha_age_ms"] as? NSNumber)?.int64Value ?? 0
        turnDetail = json["detail"] as? String ?? ""
        if let value = json["captcha_url"] as? String, !value.isEmpty { turnCaptchaURL = value }
        if turnCaptchaRequired, status == .connecting {
            connectionDetail = "VK verification required"
        } else if turnReady, status == .connecting {
            connectionDetail = "TURN is ready · starting VPN"
        } else if status == .connecting, !turnTransport.isEmpty {
            connectionDetail = turnDetail.isEmpty
                ? "TURN \(turnTransport.uppercased()) · sessions \(turnConnectedStreams)"
                : "TURN \(turnTransport.uppercased()) · \(turnDetail)"
        }
        if let error = json["last_error"] as? String, !error.isEmpty { lastError = error }
    }

    func turnCaptchaNeedsUser(automatic: Bool) -> Bool {
        turnCaptchaRequired && TURNCaptchaPolicy.needsUser(ageMilliseconds: turnCaptchaAgeMilliseconds, automatic: automatic)
    }

    private func friendlyError(_ error: Error) -> String {
        #if targetEnvironment(simulator)
        return "System VPN is unavailable in the simulator. Test the interface here and connectivity on a signed iPhone or iPad."
        #else
        let message = error.localizedDescription
        if message.localizedCaseInsensitiveContains("permission") || message.localizedCaseInsensitiveContains("entitlement") {
            return "iOS did not allow Packet Tunnel. Check signing and the Network Extensions capability for the app and extension."
        }
        return message
        #endif
    }

    private func reportDisconnectError(_ connection: NEVPNConnection) {
        connection.fetchLastDisconnectError { [weak self] error in
            Task { @MainActor in
                let message = error?.localizedDescription ?? "Packet Tunnel stopped during startup. Open the app log for details."
                RuntimeLog.write("VPN disconnected during startup: \(message)")
                self?.lastError = message
            }
        }
    }
}

private enum TunnelStartResult {
    case cancelled
    case success
    case failure(String)
}

private final class ProviderReply: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data?, Never>?
    init(_ continuation: CheckedContinuation<Data?, Never>) { self.continuation = continuation }
    func finish(_ data: Data?) {
        lock.lock()
        let reply = continuation; continuation = nil
        lock.unlock()
        reply?.resume(returning: data)
    }
}
