import Foundation
import Network
import NetworkExtension
import SwiftyXrayKit
import Darwin

final class PacketTunnelProvider: NEPacketTunnelProvider {
    // Leave room for the Swift/Go runtime and TURN lanes in the extension's
    // process budget, without shrinking the working packet/TCP/UDP limits.
    private static let tunnelPreset = XrayTuningPreset(memoryLimitMB: 24, tcpBufMaxKB: 1024,
                                                      tcpMaxInFlight: 512, udpMaxConns: 256, idleTimeoutSec: 120)
    // All lifecycle state and native start/stop operations belong to the main actor.
    @MainActor private var bridge: XrayBridge?
    @MainActor private var coreRunning = false
    @MainActor private var hasEstablishedConnection = false
    @MainActor private var panelAccess: PanelAccessGrant?
    @MainActor private var accessTask: Task<Void, Never>?
    @MainActor private var physicalDNSPort = 0
    @MainActor private var physicalDNSIdentity = ""
    @MainActor private var physicalDNSResolvers: [String] = []
    @MainActor private var probePort: Int?
    @MainActor private var probeRequest: HTTPProbeRequest?
    @MainActor private var fallbackProbePort: Int?
    @MainActor private var fallbackProbeRequest: HTTPProbeRequest?
    @MainActor private var latencyPort: Int?
    @MainActor private var latencyTask: (id: UUID, task: Task<Int?, Never>)?
    @MainActor private var routeProbeTask: Task<Int?, Never>?
    @MainActor private var routeProbeID = UUID()
    @MainActor private var systemRouteFailed = false
    @MainActor private var lifecycleTask: Task<Void, Never>?
    @MainActor private var recoveryIsAutomatic = false
    @MainActor private var trafficTask: Task<Void, Never>?
    @MainActor private var traffic = TrafficLedger()
    @MainActor private var trafficAt = Date()
    @MainActor private var monitorTask: Task<Void, Never>?
    @MainActor private var turnCaptchaTask: Task<Void, Never>?
    @MainActor private var turnCaptchaVerificationTask: Task<Void, Never>?
    @MainActor private var turnCaptchaExpiryTask: Task<Void, Never>?
    @MainActor private var turnCaptchaExpiryID = UUID()
    @MainActor private var awaitingTURNChallengeResult = false
    @MainActor private var blockedTURNChallengeID: UInt64?
    @MainActor private var generation = UUID()
    @MainActor private var stopped = true
    @MainActor private var configuration = ""
    @MainActor private var mtu = 1500
    @MainActor private var isTURN = false
    @MainActor private var isDNS = false
    @MainActor private var isManagedDNS = false
    @MainActor private var isAmnezia = false
    @MainActor private var profileID = ""
    @MainActor private var isTelemost = false
    @MainActor private var telemostRecovery: Data?
    @MainActor private var snapshot = TunnelRecoverySnapshot()
    @MainActor private var budget = RecoveryBudget()
    @MainActor private var amneziaRepairTask: Task<Void, Never>?
    @MainActor private var amneziaRepairID = UUID()
    @MainActor private var amneziaRoutesReleased = false
    @MainActor private var networkSettingsTask: Task<Void, Error>?
    #if DEBUG
    @MainActor private var diagnosticAmneziaRecoveryHold = false
    @MainActor private var diagnosticAmneziaReleaseCount = 0
    @MainActor private var diagnosticAmneziaRestoreCount = 0
    #endif
    @MainActor private var reportedAmneziaPacketFailure = false
    @MainActor private var pathMonitor: NWPathMonitor?
    @MainActor private var networkAvailable = true
    @MainActor private var networkChanged = false
    @MainActor private var networkUsesWiFi = false
    @MainActor private var receivedNetworkPath = false
    @MainActor private var physicalPathSignature: String?
    @MainActor private var physicalPathRevision: UInt64 = 0
    @MainActor private var turnMigrationTask: Task<Void, Never>?
    @MainActor private var turnMigrationID = UUID()
    @MainActor private var startCompletion: ((Error?) -> Void)?
    @MainActor private var temporaryFullTunnel = false
    @MainActor private var fullTunnelDeadline: ContinuousClock.Instant?
    @MainActor private var fullTunnelTimer: Task<Void, Never>?

    @MainActor private var savedSettings: AppSettings {
        guard let data = AppGroup.defaults.data(forKey: AppGroup.settingsKey) else { return AppSettings() }
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
        return (try? decoder.decode(AppSettings.self, from: data)) ?? AppSettings()
    }

    @MainActor private var settings: AppSettings {
        TemporaryFullTunnelPolicy.applying(to: savedSettings, isTURN: isTURN, isDNS: isDNS || isManagedDNS,
                                           isAmnezia: isAmnezia, full: temporaryFullTunnel)
    }

    @MainActor private func publishFullTunnel(pending: Bool = false, applied: Bool? = nil) -> Data? {
        let data = try? JSONEncoder().encode(TemporaryFullTunnelState(profileID: profileID,
            enabled: applied ?? temporaryFullTunnel, pending: pending))
        AppGroup.defaults.set(data, forKey: TemporaryFullTunnelPolicy.stateKey)
        return data
    }

    @MainActor private func resetFullTunnel() {
        fullTunnelTimer?.cancel(); fullTunnelTimer = nil; fullTunnelDeadline = nil
        temporaryFullTunnel = false
        _ = publishFullTunnel()
    }

    @MainActor private func setTemporaryFullTunnel(_ enabled: Bool) async -> Data? {
        guard !stopped, lifecycleTask == nil, amneziaRepairTask == nil, turnMigrationTask == nil, snapshot.phase == .connected,
              recoveryProfileIsSelected,
              TemporaryFullTunnelPolicy.supported(isTURN: isTURN, isDNS: isDNS || isManagedDNS,
                isAmnezia: isAmnezia, amneziaSplit: savedSettings.effectiveAmneziaSplitEnabled) else { return nil }
        guard enabled != temporaryFullTunnel else { return publishFullTunnel() }
        let token = generation
        let previous = temporaryFullTunnel
        fullTunnelTimer?.cancel(); fullTunnelTimer = nil; fullTunnelDeadline = nil
        _ = publishFullTunnel(pending: true)
        temporaryFullTunnel = enabled
        monitorTask?.cancel(); monitorTask = nil
        routeProbeTask?.cancel(); routeProbeTask = nil; routeProbeID = UUID()
        latencyTask?.task.cancel(); latencyTask = nil
        // Keep the OS VPN and the authenticated TURN relay; replace only Xray.
        lifecycleTask = Task { @MainActor in
            do {
                try await preparePhysicalDNS(readSystemDNS: false)
                guard valid(token) else { return }
                try startPacketEngine()
                guard valid(token) else { return }
                publish(.connected, "Connected")
                _ = publishFullTunnel()
                RuntimeLog.write("Temporary full tunnel applied: \(enabled)")
                lifecycleTask = nil
                startMonitoring()
                if enabled { startFullTunnelTimer() }
            } catch {
                guard valid(token) else { return }
                temporaryFullTunnel = previous
                resetFullTunnel()
                stopRuntime(); lifecycleTask = nil
                publish(.disconnected, "Routing could not be applied. Reconnect the VPN.")
                cancelTunnelWithError(error)
            }
        }
        await lifecycleTask?.value
        guard valid(token) else { return nil }
        return publishFullTunnel()
    }

    @MainActor private func startFullTunnelTimer() {
        let requested = savedSettings.fullTunnelMinutes ?? TemporaryFullTunnelPolicy.defaultMinutes
        let minutes = TemporaryFullTunnelPolicy.minutes.contains(requested) ? requested : TemporaryFullTunnelPolicy.defaultMinutes
        guard minutes > 0 else { return }
        let deadline = ContinuousClock.now.advanced(by: .seconds(minutes * 60))
        fullTunnelDeadline = deadline
        fullTunnelTimer = Task { @MainActor in
            do { try await ContinuousClock().sleep(until: deadline) } catch { return }
            while !Task.isCancelled, !stopped, temporaryFullTunnel, fullTunnelDeadline == deadline {
                if lifecycleTask == nil, amneziaRepairTask == nil, snapshot.phase == .connected {
                    // The expiry operation replaces this timer; do not cancel its own task.
                    fullTunnelTimer = nil
                    _ = await setTemporaryFullTunnel(false)
                    return
                }
                do { try await Task.sleep(for: .seconds(1)) } catch { return }
            }
        }
    }

    @MainActor private var automationPolicy: TunnelAutomationPolicy {
        TunnelAutomationPolicy(isTURN: isTURN, isDNS: isDNS,
                               isManagedDNS: isManagedDNS, isAmnezia: isAmnezia)
    }

    @MainActor private var recoveryProfileIsSelected: Bool {
        AppGroup.defaults.string(forKey: AppGroup.activeProfileKey).map { $0 == profileID } ?? true
    }

    @MainActor private var automaticRecoveryEnabled: Bool {
        automationPolicy.automaticRecoveryEnabled(settings)
    }

    @MainActor private var isPlainVK: Bool {
        !isTelemost && NativeTURNBridge.isPlainVK
    }

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        Task { @MainActor in
            stopped = false
            hasEstablishedConnection = false
            reportedAmneziaPacketFailure = false
            amneziaRoutesReleased = false
            #if DEBUG
            diagnosticAmneziaRecoveryHold = false
            diagnosticAmneziaReleaseCount = 0; diagnosticAmneziaRestoreCount = 0
            #endif
            NativeTURNBridge.resetTransportPreference()
            generation = UUID()
            let token = generation
            startCompletion = completionHandler
            let values = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration ?? [:]
            profileID = values["profileId"] as? String ?? ""
            isTelemost = (values["isTelemost"] as? NSNumber)?.boolValue == true
            do {
                try loadStartupConfiguration()
                panelAccess = nil
                if values["isPanelManaged"] as? Bool == true || values["panelAccess"] != nil {
                    guard let data = values["panelAccess"] as? Data else { throw PanelFailure("The subscription access record is missing.") }
                    panelAccess = try JSONDecoder().decode(PanelAccessGrant.self, from: data)
                    try PanelAccess.require(panelAccess)
                }
            } catch { finishStart(makeError(error.localizedDescription)); return }
            startAccessMonitoring(token: token)
            mtu = (values["mtu"] as? NSNumber)?.intValue ?? 1500
            isTURN = (values["isTURN"] as? NSNumber)?.boolValue == true
            isDNS = (values["isDNS"] as? NSNumber)?.boolValue == true
            isManagedDNS = (values["isManagedDNS"] as? NSNumber)?.boolValue == true
            isAmnezia = (values["isAmnezia"] as? NSNumber)?.boolValue == true
            resetFullTunnel()
            snapshot = TunnelRecoverySnapshot(profileID: profileID, maximumAttempts: settings.recoveryMaxRetries)
            snapshot.providerProcessID = Int(getpid())
            budget = RecoveryBudget()
            physicalPathSignature = nil
            networkChanged = false
            startPathMonitor()
            lifecycleTask = Task { @MainActor in
                do {
                    if isManagedDNS || isTelemost { try await waitForNetworkPath(token: token) }
                    try await preparePhysicalDNS(readSystemDNS: true)
                    try await setNetworkSettings()
                    try await startInitialRuntime(token: token)
                    guard valid(token) else { return }
                    #if targetEnvironment(macCatalyst)
                    if isAmnezia, #available(macCatalyst 18.0, *) {
                        // Finish the OS startup before sending traffic through
                        // its virtual interface. UI stays Verifying until this
                        // independent system path has actually responded.
                        publish(.verifying, "Checking system VPN traffic…")
                        finishStart(nil)
                        let latency = await measureRoute()
                        guard valid(token) else { return }
                        guard let latency else {
                            throw makeError("Amnezia system traffic did not resume. Reconnect manually.")
                        }
                        snapshot.latencyMilliseconds = latency
                    }
                    #endif
                    if isTelemost { networkChanged = false }
                    publish(.connected, "Connected")
                    finishStart(nil)
                    lifecycleTask = nil
                    startMonitoring()
                } catch {
                    guard valid(token) else { return }
                    let systemStarted = startCompletion == nil
                    stopRuntime(); PhysicalDNSRuntime.stop(); accessTask?.cancel(); accessTask = nil
                    publish(.disconnected, error.localizedDescription)
                    finishStart(makeError(error.localizedDescription))
                    lifecycleTask = nil
                    pathMonitor?.cancel(); pathMonitor = nil
                    if systemStarted { cancelTunnelWithError(error) }
                }
            }
        }
    }

    @MainActor private func loadStartupConfiguration() throws {
        telemostRecovery = isTelemost ? try RecoveryTransportStore.loadTelemost(profileID: profileID) : nil
        let stored = AppGroup.activeConfigURL.flatMap { try? String(contentsOf: $0, encoding: .utf8) }
            ?? AppGroup.defaults.string(forKey: AppGroup.activeConfigKey)
        guard let stored, !stored.isEmpty else { throw makeError("The active configuration was not found.") }
        configuration = stored
    }

    @MainActor private func startAccessMonitoring(token: UUID) {
        accessTask?.cancel()
        guard panelAccess != nil else { return }
        accessTask = Task { @MainActor in
            while valid(token) {
                do {
                    try PanelAccess.require(panelAccess)
                    try await Task.sleep(for: .seconds(1))
                } catch is CancellationError { return }
                catch {
                    stopped = true; generation = UUID()
                    lifecycleTask?.cancel(); monitorTask?.cancel(); cancelAmneziaRepair()
                    stopRuntime(); PhysicalDNSRuntime.stop(); physicalDNSPort = 0
                    reasserting = false
                    publish(.disconnected, error.localizedDescription)
                    finishStart(makeError(error.localizedDescription))
                    cancelTunnelWithError(makeError(error.localizedDescription))
                    return
                }
            }
        }
    }

    @MainActor private func preparePhysicalDNS(readSystemDNS: Bool) async throws {
        guard settings.splitTunneling?.mode != .disabled, settings.splitTunneling != nil else { return }
        let token = generation, revision = physicalPathRevision
        let network = try await PanelPhysicalNetwork.snapshot(readSystemDNS: readSystemDNS)
        guard valid(token), revision == physicalPathRevision else { throw CancellationError() }
        if physicalDNSIdentity != network.identity {
            physicalDNSIdentity = network.identity
            physicalDNSResolvers = network.dnsServers
        } else if !network.dnsServers.isEmpty { physicalDNSResolvers = network.dnsServers }
        let resolvers = physicalDNSResolvers.isEmpty ? ["1.1.1.1:53", "8.8.8.8:53"] : physicalDNSResolvers
        physicalDNSPort = PhysicalDNSRuntime.start(interface: network.interface, resolvers: resolvers)
        guard physicalDNSPort > 0 else { throw PanelFailure("Direct DNS could not start on the physical network.") }
    }

    @MainActor private func valid(_ token: UUID) -> Bool { !stopped && generation == token && !Task.isCancelled }

    @MainActor private func startInitialRuntime(token: UUID) async throws {
        // A transport handshake can work while real VPN traffic fails. Advance
        // once during initial startup; later recovery uses the existing budget.
        for attempt in 0..<2 {
            do {
                try await startRuntime(token: token)
                guard valid(token) else { throw CancellationError() }
                let turnProxy = isTURN && !isDNS && !isManagedDNS
                let builtInDNS = profileID == ManagedDNSSettings.builtInProfileID
                if NativeTURNBridge.usingRecovery || isAmnezia || turnProxy || builtInDNS {
                    if isTelemost {
                        publish(.verifying, "Checking internet access through Telemost…")
                    } else {
                        publish(.verifying, isAmnezia ? "Checking Amnezia data transfer…" : (turnProxy ? "Checking TURN data transfer…" : (builtInDNS ? "Checking DNS data transfer…" : "Checking VPN through the fallback route")))
                    }
                    let probeStarted = ProcessInfo.processInfo.systemUptime
                    let latency = await measureRoutePreservingTURNChallenge(token: token)
                    guard valid(token) else { throw CancellationError() }
                    if isTelemost {
                        let elapsed = Int((ProcessInfo.processInfo.systemUptime - probeStarted) * 1000)
                        RuntimeLog.write("Telemost HTTPS check \(latency == nil ? "failed" : "passed") in \(elapsed) ms")
                    }
                    guard let latency else {
                        if isTelemost {
                            throw makeError("Telemost joined the call, but internet traffic did not pass through the tunnel.")
                        }
                        throw makeError(isAmnezia ? "Amnezia is not transferring data. Check the key and server availability." : (turnProxy ? "TURN is not transferring data. Check the server and try again." : (builtInDNS ? "The built-in DNS tunnel is not transferring data on this network. Try another connection." : "The fallback route failed the VPN check.")))
                    }
                    snapshot.latencyMilliseconds = latency
                }
                return
            } catch {
                // An older, cancelled startup must not stop a newer generation.
                guard valid(token) else { throw CancellationError() }
                // A ready Telemost session can stall without closing its media link.
                let retryTelemost = isTelemost && snapshot.phase == .verifying
                let advance = retryTelemost || NativeTURNBridge.recordRouteFailure()
                stopRuntime()
                if attempt == 1 || !advance { throw error }
                if retryTelemost {
                    publish(.startingTURN, "Reconnecting Telemost…")
                    try await Task.sleep(for: .milliseconds(450))
                }
            }
        }
    }

    @MainActor private func finishStart(_ error: Error?) {
        let completion = startCompletion; startCompletion = nil
        completion?(error)
    }

    @MainActor private func startRuntime(token: UUID) async throws {
        guard valid(token), !(isTURN || isAmnezia) || recoveryProfileIsSelected else { throw CancellationError() }
        try PanelAccess.require(panelAccess)
        try await preparePhysicalDNS(readSystemDNS: false)
        guard valid(token), !(isTURN || isAmnezia) || recoveryProfileIsSelected else { throw CancellationError() }
        Self.tunnelPreset.apply()
        let startingDetail = isTelemost ? "Joining Telemost…" :
            ((isDNS || isManagedDNS) ? "Starting DNS tunnel…" : (isTURN ? "Starting TURN…" : "Starting VPN…"))
        publish(isTURN ? .startingTURN : .startingCore, startingDetail)
        AppGroup.defaults.removeObject(forKey: AppGroup.turnStatusKey)
        let builtInNetwork = profileID == ManagedDNSSettings.builtInProfileID ? try await PanelPhysicalNetwork.snapshot(readSystemDNS: false) : nil
        guard valid(token), !(isTURN || isAmnezia) || recoveryProfileIsSelected else { throw CancellationError() }
        let transportStarted = ProcessInfo.processInfo.systemUptime
        try startTransport(builtInInterface: builtInNetwork?.interface)
        startTURNCaptchaMonitoring()
        if isTURN { try await waitForTURNReady(token: token) }
        guard valid(token), !(isTURN || isAmnezia) || recoveryProfileIsSelected else { throw CancellationError() }
        if isTelemost {
            let elapsed = Int((ProcessInfo.processInfo.systemUptime - transportStarted) * 1000)
            RuntimeLog.write("Telemost media and relay ready in \(elapsed) ms")
        }
        publish(.startingCore, "Starting VPN…")
        try startPacketEngine()
    }

    @MainActor private func startTransport(builtInInterface: String?) throws {
        if isTelemost {
            guard let telemostRecovery else { throw makeError("The Telemost configuration is missing.") }
            try NativeTURNBridge.startTelemost(telemostRecovery)
            return
        }
        try NativeTURNBridge.startIfNeeded(isTURN: isTURN, isDNS: isDNS, isManagedDNS: isManagedDNS,
                                           usingWiFi: networkUsesWiFi, builtInInterface: builtInInterface)
    }

    @MainActor private func startPacketEngine() throws {
        let recovery = NativeTURNBridge.usingRecovery
        let plainTURN = isTURN && !isDNS && !isManagedDNS && !recovery
        let needsFallbackProbe = isTelemost || plainTURN || isAmnezia
        let ports = try SwiftyXray.getFreePorts(needsFallbackProbe ? 3 : 2)
        guard ports.count == (needsFallbackProbe ? 3 : 2), let port = ports.first, let latencyPort = ports.last,
              let request = HTTPProbeRequest(plainTURN ? HTTPProbeRequest.turnURL : (recovery ? HTTPProbeRequest.recoveryURL : settings.connectivityTestURL),
                                             expectedStatusCode: recovery ? 204 : nil) else {
            throw makeError("Enter a valid HTTP or HTTPS probe URL.")
        }
        let next = bridge ?? XrayBridge(packetFlow: packetFlow)
        let fallbackPort = needsFallbackProbe ? ports[1] : nil
        let fallbackRequest: HTTPProbeRequest?
        if isTelemost {
            fallbackRequest = HTTPProbeRequest(HTTPProbeRequest.turnURL, expectedStatusCode: 200)
        } else if isAmnezia {
            fallbackRequest = HTTPProbeRequest(HTTPProbeRequest.systemFallbackURL, expectedStatusCode: 200)
        } else {
            fallbackRequest = plainTURN ? HTTPProbeRequest.turnFallback(settings.connectivityTestURL) : nil
        }
        bridge = next
        do {
            var runtimeSettings = settings
            if physicalDNSPort > 0 { runtimeSettings.directDNS = "tcp+local://127.0.0.1:\(physicalDNSPort)" }
            let turn = isTURN
            let restoreTURNRouting = isTURN && !isDNS && !isManagedDNS
            RuntimeLog.write("Starting Xray: 24 MB heap, full TCP/UDP limits; routing \(restoreTURNRouting ? "original TURN" : "profile default")")
            // Keep direct traffic flowing while a remote transport authenticates;
            // replace the packet engine only once its replacement is ready.
            next.stop(); coreRunning = false
            SwiftyXray.setIPv6Enabled(runtimeSettings.ipv6Enabled)
            var appliedRouting = ""
            try next.start(config: .json(configuration), dataDir: geoDataDirectory(),
                           finalConfigPath: FileManager.default.temporaryDirectory.appendingPathComponent("kindlyvpn-xray.json"),
                           preset: Self.tunnelPreset,
                           configTransform: {
                               var root = TunnelConfiguration.applying(to: $0, settings: runtimeSettings, isTURN: turn,
                                                                       restoreTURNRouting: restoreTURNRouting)
                               if let logURL = RuntimeLog.xrayLogURL {
                                   var log = root["log"] as? [String: Any] ?? [:]
                                   if turn { log["loglevel"] = runtimeSettings.logLevel }
                                   log["error"] = logURL.path
                                   root["log"] = log
                               }
                               root = ProbeConfiguration.adding(to: root, port: port, request: request)
                               if let fallbackPort, let fallbackRequest {
                                   root = ProbeConfiguration.adding(to: root, port: fallbackPort, request: fallbackRequest, tag: "kindly-health-fallback")
                               }
                               root = ProbeConfiguration.adding(to: root, port: latencyPort, request: HTTPProbeRequest.realDelay, tag: "kindly-latency")
                               appliedRouting = SplitTunnelRouting.diagnosticJSON(root: root, settings: runtimeSettings)
                               return root
                           })
            coreRunning = true
            RuntimeLog.write("Routing applied v1 " + appliedRouting)
            probePort = port; probeRequest = request
            fallbackProbePort = fallbackPort; fallbackProbeRequest = fallbackRequest
            self.latencyPort = latencyPort
            startTrafficSampling()
        } catch { next.stop(); throw error }
    }

    /// Challenge lifetime belongs to the native clock, not an individual probe
    /// or an open browser. This observer also runs when automatic recovery is off.
    @MainActor private func startTURNCaptchaMonitoring() {
        guard isTURN, !isDNS, !isManagedDNS, isPlainVK, turnCaptchaTask == nil else { return }
        turnCaptchaTask = Task { @MainActor in
            while !stopped && !Task.isCancelled {
                _ = refreshTURNChallenge()
                let delay = blockedTURNChallengeID == nil ? 1_000 : 250
                do { try await Task.sleep(for: .milliseconds(delay)) } catch { return }
            }
        }
    }

    @MainActor private func currentTURNStatusData() -> Data? {
        guard let data = NativeTURNBridge.statusData(),
              var object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        object["captcha_blocks_route"] = blockedTURNChallengeID != nil &&
            blockedTURNChallengeID == (object["captcha_id"] as? NSNumber)?.uint64Value
        return try? JSONSerialization.data(withJSONObject: object, options: .sortedKeys)
    }

    /// Returns whether a native challenge is pending, including optional lanes.
    /// A failed route becomes blocked until the same challenge completes.
    @MainActor @discardableResult private func refreshTURNChallenge(blocking: Bool = false) -> Bool {
        guard isTURN, !isDNS, !isManagedDNS, isPlainVK,
              let state = NativeTURNBridge.status() else { return false }
        let completedBlockedChallenge = blockedTURNChallengeID != nil && !state.captchaRequired
        if !state.captchaRequired || blockedTURNChallengeID != state.captchaID { blockedTURNChallengeID = nil }
        if state.captchaRequired && (blocking || !state.ready) {
            blockedTURNChallengeID = state.captchaID
            awaitingTURNChallengeResult = true
        }
        if let data = currentTURNStatusData(), data != AppGroup.defaults.data(forKey: AppGroup.turnStatusKey) {
            AppGroup.defaults.set(data, forKey: AppGroup.turnStatusKey)
        }
        if !state.ready && (TURNCaptchaPolicy.terminalFailure(state.lastError) ||
                           (!state.running && awaitingTURNChallengeResult)) {
            stopForTURNChallengeFailure(); return false
        }
        if completedBlockedChallenge && coreRunning && lifecycleTask == nil && turnMigrationTask == nil {
            let token = generation
            turnCaptchaVerificationTask?.cancel()
            turnCaptchaVerificationTask = Task { @MainActor in
                let latency = await measureRoutePreservingTURNChallenge(token: token)
                guard valid(token), lifecycleTask == nil, turnMigrationTask == nil else { return }
                guard let latency else {
                    if automaticRecoveryEnabled { beginRecovery(reason: "TURN did not resume after VK verification.") }
                    else { stopForTURNChallengeFailure() }
                    return
                }
                snapshot.latencyMilliseconds = latency
                publish(.connected, "Connected")
                startMonitoring()
            }
        }
        if state.captchaRequired && blockedTURNChallengeID != nil {
            if TURNCaptchaPolicy.expired(ageMilliseconds: state.captchaAgeMilliseconds ?? 0) {
                // Optional lanes may have recovered while their old challenge
                // remained open. One bounded traffic check prevents stopping a
                // working VPN merely because that browser was not completed.
                if state.ready && coreRunning {
                    if turnCaptchaExpiryTask == nil {
                        let token = generation, challenge = state.captchaID
                        let identifier = UUID(); turnCaptchaExpiryID = identifier
                        turnCaptchaExpiryTask = Task { @MainActor in
                            defer { if turnCaptchaExpiryID == identifier { turnCaptchaExpiryTask = nil } }
                            let latency = await measureRoute(deadline: ProcessInfo.processInfo.systemUptime + 5)
                            guard valid(token), blockedTURNChallengeID == challenge,
                                  NativeTURNBridge.status()?.captchaID == challenge else { return }
                            if let latency {
                                acceptTURNChallengeRoute()
                                if lifecycleTask == nil && turnMigrationTask == nil {
                                    snapshot.latencyMilliseconds = latency; publish(.connected, "Connected"); startMonitoring()
                                }
                            }
                            else { stopForTURNChallengeFailure() }
                        }
                    }
                } else if NativeTURNBridge.status()?.captchaID == state.captchaID { stopForTURNChallengeFailure() }
                return true
            }
            let settingsData = AppGroup.defaults.data(forKey: AppGroup.turnSettingsKey)
            let automatic = settingsData.flatMap { try? JSONDecoder().decode(TURNSettings.self, from: $0) }?.isAutoCaptchaEnabled ?? true
            publish(.captcha, TURNCaptchaPolicy.needsUser(ageMilliseconds: state.captchaAgeMilliseconds ?? 0, automatic: automatic)
                    ? "Complete VK verification in TnDtun." : "Verifying VK…")
        }
        return state.captchaRequired
    }

    @MainActor private func acceptTURNChallengeRoute() {
        blockedTURNChallengeID = nil; awaitingTURNChallengeResult = false
        turnCaptchaExpiryID = UUID()
        turnCaptchaExpiryTask?.cancel(); turnCaptchaExpiryTask = nil
    }

    @MainActor private func stopForTURNChallengeFailure() {
        guard !stopped else { return }
        let error = makeError("VK verification was not completed. Reconnect to try again.")
        stopped = true; generation = UUID()
        lifecycleTask?.cancel(); lifecycleTask = nil
        monitorTask?.cancel(); monitorTask = nil
        pathMonitor?.cancel(); pathMonitor = nil
        accessTask?.cancel(); accessTask = nil
        resetFullTunnel(); stopRuntime()
        PhysicalDNSRuntime.stop(); physicalDNSPort = 0
        reasserting = false
        AppGroup.defaults.removeObject(forKey: AppGroup.turnStatusKey)
        publish(.disconnected, error.localizedDescription)
        finishStart(error)
        cancelTunnelWithError(error)
    }

    @MainActor private func waitForTURNReady(token: UUID, maximumWait: TimeInterval? = nil) async throws {
        var started = ProcessInfo.processInfo.systemUptime
        var captchaPending = false
        var notified = false
        let turnData = isTelemost ? nil : AppGroup.defaults.data(forKey: AppGroup.turnSettingsKey)
        let turnSettings = turnData.flatMap { try? JSONDecoder().decode(TURNSettings.self, from: $0) } ?? TURNSettings()
        while valid(token) {
            _ = refreshTURNChallenge()
            guard valid(token) else { throw CancellationError() }
            if let data = currentTURNStatusData() { AppGroup.defaults.set(data, forKey: AppGroup.turnStatusKey) }
            if let status = NativeTURNBridge.status() {
                if status.ready, !isTelemost || status.transport == "conference" { return }
                if !status.running {
                    if isTelemost { throw makeError("Could not establish the Telemost link. Check the invitation and server.") }
                    throw makeError(status.lastError ?? "TURN stopped unexpectedly.")
                }
                if status.captchaRequired != captchaPending {
                    captchaPending = status.captchaRequired
                    started = ProcessInfo.processInfo.systemUptime
                }
                if captchaPending {
                    _ = refreshTURNChallenge(blocking: true)
                    guard valid(token) else { throw CancellationError() }
                    if !notified && !turnSettings.isAutoCaptchaEnabled {
                        notified = true
                        ConnectionNotifications.post(title: "VK verification", body: "Open TnDtun to complete verification.", enabled: settings.recoveryNotificationsEnabled)
                    }
                    try await Task.sleep(for: .milliseconds(250))
                    continue
                }
            }
            if let maximumWait, ProcessInfo.processInfo.systemUptime - started >= maximumWait {
                throw makeError("TURN relay repair timed out.")
            }
            let timeout = NativeTURNBridge.usingRecovery ? RecoveryTransportStore.readyTimeout : ConnectionDropPolicy.turnReadyTimeout(captchaPending: captchaPending, autoCaptcha: turnSettings.isAutoCaptchaEnabled)
            if ProcessInfo.processInfo.systemUptime - started >= timeout {
                if isTelemost { throw makeError("Telemost did not join the call in time. Check the invitation and network.") }
                throw makeError((isDNS || isManagedDNS) ? "The DNS tunnel is unavailable on this network. Choose another connection." : (captchaPending ? "VK verification was not completed in time." : "TURN relay sessions could not be established in time."))
            }
            try await Task.sleep(for: .milliseconds(250))
        }
        throw CancellationError()
    }

    @MainActor private func startPathMonitor() {
        pathMonitor?.cancel()
        receivedNetworkPath = false
        let monitor = NWPathMonitor()
        let token = generation
        monitor.pathUpdateHandler = { [weak self] path in
            Task { @MainActor in
                guard let self, self.generation == token, !self.stopped else { return }
                let selectedInterfaces = path.availableInterfaces.filter {
                    $0.type != .other && path.usesInterfaceType($0.type)
                }
                let interfaces = Set(selectedInterfaces.map { "\($0.type):\($0.name)" }).sorted().joined(separator: ",")
                // Installing utun can briefly yield a satisfied path containing
                // only virtual interfaces. It isn't a Wi-Fi/cellular handoff.
                if self.isTelemost, path.status == .satisfied, interfaces.isEmpty { return }
                let addresses = (self.isAmnezia || (self.isTURN && self.isPlainVK))
                    ? PanelPhysicalNetwork.addressIdentity(interfaces: selectedInterfaces.map(\.name)) : ""
                let signature = "\(path.status):\(interfaces):\(addresses)"
                // Installing our own virtual route must not look like a change
                // of Wi-Fi/cellular and force a restart of a healthy transport.
                let changed = self.physicalPathSignature.map { $0 != signature } ?? false
                self.physicalPathSignature = signature
                self.networkAvailable = path.status == .satisfied
                if self.networkAvailable { self.networkUsesWiFi = path.usesInterfaceType(.wifi) }
                self.receivedNetworkPath = true
                self.networkChanged = self.networkChanged || changed
                if changed {
                    self.physicalPathRevision &+= 1
                    RuntimeLog.write("Physical network changed: \(signature)")
                    let resumableTURN = !self.isTelemost && self.hasEstablishedConnection && self.lifecycleTask == nil &&
                        NativeTURNBridge.supportsConnectionResume
                    if resumableTURN {
                        // Physical sockets must follow Wi-Fi/cellular even
                        // when the optional automatic-reconnect switch is off.
                        self.migrateResumableTURN()
                    }
                    if self.hasEstablishedConnection, self.automaticRecoveryEnabled, self.lifecycleTask != nil {
                        // A repair awaiting old-network credentials must not
                        // later bind its helper on the newly selected network.
                        self.beginRecovery(reason: "Network changed during recovery", networkSwitch: true)
                        return
                    }
                    if self.isAmnezia, self.hasEstablishedConnection, self.networkAvailable {
                        self.refreshAmneziaTransport()
                    }
                    // Direct DNS follows the physical network even when the user
                    // disables automatic VPN recovery. This never fetches a panel.
                    if self.networkAvailable && !resumableTURN { try? await self.preparePhysicalDNS(readSystemDNS: false) }
                    guard self.valid(token), self.lifecycleTask == nil else { return }
                    // Selecting a configured Wi-Fi/cellular resolver is a DNS
                    // profile change, not a periodic health check or retry.
                    if self.dnsResolverNeedsSwitch {
                        await self.applyDNSNetworkSelection(token: token)
                    }
                }
            }
        }
        pathMonitor = monitor
        monitor.start(queue: DispatchQueue(label: "com.kindlyvpn.path"))
    }

    @MainActor private func waitForNetworkPath(token: UUID) async throws {
        // Observe the physical route before installing the VPN's virtual route.
        let deadline = ProcessInfo.processInfo.systemUptime + 2
        while (!receivedNetworkPath || (isTelemost && !networkAvailable)) && ProcessInfo.processInfo.systemUptime < deadline {
            guard valid(token) else { throw CancellationError() }
            try await Task.sleep(for: .milliseconds(20))
        }
        guard valid(token) else { throw CancellationError() }
    }

    @MainActor private var dnsResolverNeedsSwitch: Bool {
        guard isManagedDNS, networkAvailable, receivedNetworkPath,
              let current = NativeTURNBridge.currentDNSResolver,
              let dns = try? ManagedDNSStore.load().validated() else { return false }
        return current != dns.effectiveResolver(usingWiFi: networkUsesWiFi)
    }

    @MainActor private func applyDNSNetworkSelection(token: UUID) async {
        guard valid(token), lifecycleTask == nil, dnsResolverNeedsSwitch else { return }
        do {
            let network = profileID == ManagedDNSSettings.builtInProfileID
                ? try await PanelPhysicalNetwork.snapshot(readSystemDNS: false) : nil
            guard valid(token), lifecycleTask == nil, dnsResolverNeedsSwitch else { return }
            // Reconfigure only the native DNSTT session when its configured
            // resolver changes. Keep the VPN/core and address rules in place;
            // no common watchdog, HTTP probe, retry budget or On Demand.
            try NativeTURNBridge.startIfNeeded(isTURN: isTURN, isDNS: isDNS, isManagedDNS: isManagedDNS,
                                               usingWiFi: networkUsesWiFi, builtInInterface: network?.interface)
        } catch {
            RuntimeLog.write("DNS network selection failed: \(error.localizedDescription)")
        }
    }

    @MainActor private func startMonitoring() {
        monitorTask?.cancel(); monitorTask = nil
        if isAmnezia { startAmneziaMonitoring(); return }
        guard automaticRecoveryEnabled, lifecycleTask == nil, turnMigrationTask == nil else { return }
        let token = generation
        monitorTask = Task { @MainActor in
            var schedule = BackgroundProbeSchedule(now: ProcessInfo.processInfo.systemUptime)
            var turnUnreadySince: TimeInterval?
            while valid(token) {
                do { try await Task.sleep(for: .seconds(1)) } catch { return }
                guard valid(token), automaticRecoveryEnabled else { return }
                let now = ProcessInfo.processInfo.systemUptime
                if let failure = bridge?.forwardingFailure {
                    beginRecovery(reason: "VPN packet forwarding failed: " + failure); return
                }
                _ = refreshTURNChallenge()
                guard valid(token) else { return }
                if isTURN, let data = currentTURNStatusData() { AppGroup.defaults.set(data, forKey: AppGroup.turnStatusKey) }
                if isTURN, let state = NativeTURNBridge.status(), !state.running {
                    beginRecovery(reason: state.lastError ?? "TURN stopped unexpectedly."); return
                }
                if blockedTURNChallengeID != nil && NativeTURNBridge.status()?.ready != true { continue }
                if !networkAvailable { beginRecovery(reason: "No internet connection."); return }
                if networkChanged {
                    networkChanged = false
                    beginRecovery(reason: "Network changed · restoring the tunnel", networkSwitch: true); return
                }
                if isTURN, let state = NativeTURNBridge.status(), !state.ready {
                    if turnUnreadySince == nil { turnUnreadySince = now }
                    // A previously working relay disappearing is not an initial
                    // login. Give lane maintainers a short grace period, rather
                    // than waiting the full three-minute startup budget.
                    let timeout = ConnectionDropPolicy.transportDropGrace
                    if now - (turnUnreadySince ?? now) >= timeout { beginRecovery(reason: "TURN stopped transferring data."); return }
                    continue
                }
                turnUnreadySince = nil
                let verificationFinished = snapshot.phase == .captcha
                guard verificationFinished || networkChanged || schedule.isDue(now: now, interval: settings.backgroundProbeInterval(turnProxy: true)) else { continue }
                if verificationFinished { publish(.verifying, "Checking VPN data transfer…") }
                networkChanged = false
                let revision = physicalPathRevision
                let latency = await measureRoute()
                guard valid(token), automaticRecoveryEnabled, turnMigrationTask == nil else { return }
                guard revision == physicalPathRevision else { continue }
                if latency == nil && refreshTURNChallenge(blocking: true) { continue }
                schedule.completed(at: ProcessInfo.processInfo.systemUptime)
                snapshot.latencyMilliseconds = latency
                if latency != nil { acceptTURNChallengeRoute(); publish(.connected, "Connected") }
                // TURN has already tried two independent HTTP endpoints through
                // the proxy. If both fail, restore it in this check cycle.
                if budget.recordProbe(succeeded: latency != nil, failureThreshold: 1) {
                    beginRecovery(reason: "VPN stopped transferring data."); return
                }
            }
        }
    }

    @MainActor private func beginRecovery(reason: String, manual: Bool = false, networkSwitch: Bool = false) {
        guard !stopped, recoveryProfileIsSelected, automationPolicy.permitsRecovery(manual: manual, settings: settings) else { return }
        if !manual && refreshTURNChallenge(blocking: true) { return }
        guard !stopped else { return }
        guard manual || networkSwitch || lifecycleTask == nil else { return }
        cancelAmneziaRepair()
        cancelTURNMigration()
        let wasFullTunnel = temporaryFullTunnel
        resetFullTunnel()
        let repairRelay = !wasFullTunnel && !manual && automaticRecoveryEnabled && hasEstablishedConnection &&
            coreRunning && bridge?.forwardingFailure == nil && isPlainVK
        if repairRelay { NativeTURNBridge.recordTransportFailure(previouslyConnected: true, networkSwitch: networkSwitch) }
        recoveryIsAutomatic = !manual
        if !manual { NativeTURNBridge.recordRouteFailure() }
        lifecycleTask?.cancel(); monitorTask?.cancel(); monitorTask = nil
        routeProbeTask?.cancel(); routeProbeTask = nil; routeProbeID = UUID()
        generation = UUID()
        let token = generation
        startAccessMonitoring(token: token)
        startPathMonitor()
        budget = RecoveryBudget()
        networkChanged = false
        snapshot.attempt = 0
        snapshot.latencyMilliseconds = nil
        reasserting = !(repairRelay && NativeTURNBridge.supportsConnectionResume)
        publish(.stopping, reason)
        if !manual && !networkSwitch {
            ConnectionNotifications.post(title: "VPN connection lost", body: reason + " Reconnecting automatically.", enabled: settings.recoveryNotificationsEnabled)
        }
        if !repairRelay { stopRuntime(preserveDirectTraffic: true) }
        lifecycleTask = Task { @MainActor in
            defer {
                // Turning automation off is not Disconnect. Leave a current
                // VPN/core in place and stop this recovery without reasserting.
                if valid(token), recoveryProfileIsSelected, recoveryIsAutomatic,
                   !automaticRecoveryEnabled, lifecycleTask != nil {
                    lifecycleTask = nil; reasserting = false
                    snapshot.latencyMilliseconds = nil
                    publish(.failed, "Connection unavailable. Automatic reconnection is disabled.")
                }
            }
            if repairRelay {
                do {
                    let latency = try await repairTURNRelay(token: token)
                    guard valid(token), recoveryProfileIsSelected, automaticRecoveryEnabled else { return }
                    completeRecovery(latency: latency, networkSwitch: networkSwitch)
                    return
                } catch {
                    guard valid(token), recoveryProfileIsSelected, automaticRecoveryEnabled else { return }
                    RuntimeLog.write("TURN relay-only repair failed; rebuilding the packet engine: " + error.localizedDescription)
                    reasserting = true
                    stopRuntime(preserveDirectTraffic: true)
                }
            }
            while valid(token) && recoveryProfileIsSelected && automationPolicy.permitsRecovery(manual: manual, settings: settings) {
                if !networkAvailable {
                    guard automaticRecoveryEnabled else {
                        reasserting = false; lifecycleTask = nil
                        publish(.disconnected, "No internet connection. Reconnect manually.")
                        cancelTunnelWithError(makeError("No internet connection."))
                        return
                    }
                    publish(.waitingForNetwork, "Waiting for internet access. No attempts are used.")
                    do { try await Task.sleep(for: .seconds(1)) } catch { return }
                    continue
                }
                publish(.retryWait, "Restoring the tunnel…")
                guard valid(token), automationPolicy.permitsRecovery(manual: manual, settings: settings) else { break }
                switch budget.next(networkAvailable: networkAvailable, maximum: settings.recoveryMaxRetries) {
                case .waitForNetwork: continue
                case .exhausted:
                    publish(.retryWait, isTelemost
                        ? "Telemost is not transferring data. Retrying in 30 seconds…"
                        : "The server is unavailable. Retrying automatically in 30 seconds…")
                    do { try await Task.sleep(for: .seconds(ConnectionDropPolicy.retryCooldown)) } catch { return }
                    guard valid(token) else { return }
                    budget.resumeAfterCooldown(); snapshot.attempt = 0
                    continue
                case .attempt(let count): snapshot.attempt = count
                }
                do {
                    if isManagedDNS || isTelemost { try await waitForNetworkPath(token: token) }
                    if isAmnezia {
                        // A manually requested reconnect refreshes system routes and DNS.
                        try await setNetworkSettings()
                        guard valid(token) else { return }
                    }
                    try await startRuntime(token: token)
                    guard valid(token) else { return }
                    publish(.verifying, isTelemost ? "Checking internet access through Telemost…" : "Checking data transfer…")
                    if !isTelemost { try await Task.sleep(for: .seconds(1)) }
                    let latency = await measureRoutePreservingTURNChallenge(token: token)
                    guard valid(token) else { return }
                    guard let latency else {
                        throw makeError("VPN is not transferring data.")
                    }
                    completeRecovery(latency: latency, networkSwitch: networkSwitch)
                    return
                } catch {
                    guard valid(token) else { return }
                    guard automaticRecoveryEnabled else {
                        // A manual attempt is one attempt for Amnezia/DNS,
                        // regardless of the stored TURN automation switch.
                        reasserting = false; lifecycleTask = nil
                        publish(.disconnected, error.localizedDescription)
                        cancelTunnelWithError(error)
                        return
                    }
                    publish(.stopping, error.localizedDescription)
                    NativeTURNBridge.recordRouteFailure()
                    stopRuntime(preserveDirectTraffic: true)
                }
            }
            guard valid(token) else { return }
            if recoveryIsAutomatic, !automaticRecoveryEnabled { return }
            publish(.disconnected, "Automatic reconnection is disabled.")
            cancelTunnelWithError(nil)
        }
    }

    @MainActor private func repairTURNRelay(token: UUID) async throws -> Int {
        publish(.startingTURN, "Repairing TURN relay…")
        return try await TURNRelayRepair.run(
            isCurrent: { self.valid(token) && self.recoveryProfileIsSelected && self.automaticRecoveryEnabled && self.nativeVKRepairAllowed },
            resume: {
                guard NativeTURNBridge.supportsConnectionResume else { return nil }
                return try await self.resumeTURNRoute(token: token) {
                    self.automaticRecoveryEnabled && self.nativeVKRepairAllowed
                }
            },
            stop: { NativeTURNBridge.stop() },
            prepare: {
                while !self.networkAvailable {
                    guard self.valid(token), self.automaticRecoveryEnabled else { throw CancellationError() }
                    self.publish(.waitingForNetwork, "Waiting for internet access.")
                    try await Task.sleep(for: .seconds(1))
                }
                try await self.preparePhysicalDNS(readSystemDNS: false)
            },
            start: {
                // No await between the current-generation check and start;
                // Stop and profile replacement are serialized on MainActor.
                try PanelAccess.require(self.panelAccess)
                try NativeTURNBridge.startIfNeeded(isTURN: true, usingWiFi: self.networkUsesWiFi)
                self.startTURNCaptchaMonitoring()
            },
            waitForReady: { try await self.waitForTURNReady(token: token, maximumWait: 60) },
            verify: {
                self.publish(.verifying, "Checking TURN DNS and HTTPS…")
                return await self.measureRoutePreservingTURNChallenge(token: token)
            })
    }

    @MainActor private func cancelTURNMigration() {
        turnMigrationID = UUID()
        turnMigrationTask?.cancel(); turnMigrationTask = nil
    }

    /// Refresh only physical relay sessions. Logical v2 TCP, Xray, routing,
    /// temporary full-tunnel selection and the OS VPN remain alive.
    @MainActor private func migrateResumableTURN() {
        guard !stopped, recoveryProfileIsSelected, coreRunning, hasEstablishedConnection,
              lifecycleTask == nil, NativeTURNBridge.supportsConnectionResume else { return }
        cancelTURNMigration()
        monitorTask?.cancel(); monitorTask = nil
        routeProbeTask?.cancel(); routeProbeTask = nil; routeProbeID = UUID()
        let token = generation, identifier = turnMigrationID
        let revision = physicalPathRevision
        snapshot.latencyMilliseconds = nil
        // The OS VPN stays connected while v2 attaches replacement lanes.
        // Reasserting would report a wider disconnect to applications that
        // could otherwise continue using their original logical TCP stream.
        reasserting = false
        publish(.verifying, "Restoring TURN network…")
        turnMigrationTask = Task { @MainActor in
            defer {
                if generation == token, turnMigrationID == identifier {
                    turnMigrationTask = nil; reasserting = false
                }
            }
            let current = {
                self.valid(token) && self.recoveryProfileIsSelected && self.lifecycleTask == nil &&
                self.turnMigrationID == identifier && self.physicalPathRevision == revision
            }
            var latency: Int?
            do { latency = try await resumeTURNRoute(token: token, isCurrent: current) }
            catch is CancellationError { return }
            catch { RuntimeLog.write("TURN network refresh failed: " + error.localizedDescription) }
            guard current() else { return }
            turnMigrationTask = nil; reasserting = false
            networkChanged = false
            if let latency {
                budget.restored(); snapshot.latencyMilliseconds = latency
                publish(.connected, "Connected")
                startMonitoring()
            } else if automaticRecoveryEnabled {
                beginRecovery(reason: "TURN network did not restore data transfer", networkSwitch: true)
            } else {
                publish(.failed, "Connection unavailable. Reconnect manually.")
            }
        }
    }

    @MainActor private func resumeTURNRoute(token: UUID, isCurrent: () -> Bool) async throws -> Int? {
        var deadline = ProcessInfo.processInfo.systemUptime + 30
        while !networkAvailable {
            guard valid(token), isCurrent() else { throw CancellationError() }
            guard ProcessInfo.processInfo.systemUptime < deadline else { return nil }
            try await Task.sleep(for: .milliseconds(250))
        }
        guard valid(token), isCurrent() else { throw CancellationError() }
        try PanelAccess.require(panelAccess)
        try await preparePhysicalDNS(readSystemDNS: false)
        guard valid(token), isCurrent() else { throw CancellationError() }
        guard NativeTURNBridge.refreshResumableNetwork() else { return nil }
        while true {
            guard valid(token), isCurrent() else { throw CancellationError() }
            if refreshTURNChallenge() && blockedTURNChallengeID != nil {
                guard valid(token), isCurrent() else { throw CancellationError() }
                deadline = ProcessInfo.processInfo.systemUptime + 30
                if NativeTURNBridge.status()?.ready != true {
                    try await Task.sleep(for: .milliseconds(250))
                    continue
                }
            }
            guard ProcessInfo.processInfo.systemUptime < deadline else { return nil }
            let latency = await measureRoute(deadline: min(deadline, ProcessInfo.processInfo.systemUptime + 5))
            guard valid(token), isCurrent() else { throw CancellationError() }
            if latency == nil && refreshTURNChallenge(blocking: true) { continue }
            if let latency { acceptTURNChallengeRoute(); return latency }
            try await Task.sleep(for: .milliseconds(500))
        }
    }

    /// A new challenge may arrive during the final probe. Preserve its browser
    /// and native session rather than reporting a failed attempt to the caller.
    @MainActor private func measureRoutePreservingTURNChallenge(token: UUID) async -> Int? {
        while valid(token) {
            if refreshTURNChallenge() && blockedTURNChallengeID != nil {
                do { try await waitForTURNReady(token: token) } catch { return nil }
                guard valid(token) else { return nil }
            }
            let latency = await measureRoute()
            guard valid(token) else { return nil }
            if latency == nil && refreshTURNChallenge(blocking: true) { continue }
            if latency != nil { acceptTURNChallengeRoute() }
            return latency
        }
        return nil
    }

    @MainActor private var nativeVKRepairAllowed: Bool {
        automationPolicy.isTURNProxy && isPlainVK && coreRunning && bridge?.forwardingFailure == nil
    }

    @MainActor private func completeRecovery(latency: Int, networkSwitch: Bool) {
        guard recoveryProfileIsSelected else { return }
        budget.restored(); snapshot.attempt = 0; snapshot.latencyMilliseconds = latency
        reasserting = false
        publish(.connected, "Connection restored · \(latency) ms")
        if !networkSwitch {
            ConnectionNotifications.post(title: "Connection restored", body: "VPN is working · \(latency) ms", enabled: settings.recoveryNotificationsEnabled)
        }
        lifecycleTask = nil
        startMonitoring()
    }

    @MainActor private func publish(_ phase: RecoveryPhase, _ detail: String) {
        if phase == .connected { hasEstablishedConnection = true }
        if phase == .connected, snapshot.phase != .connected {
            // A verified working route supersedes any old CAPTCHA/retry alert.
            ConnectionNotifications.clear()
        }
        if snapshot.phase != phase || snapshot.detail != detail {
            RuntimeLog.write("Tunnel \(phase.rawValue): \(detail)")
        }
        snapshot.phase = phase; snapshot.detail = detail; snapshot.updatedAt = Date()
        snapshot.maximumAttempts = settings.recoveryMaxRetries
        AppGroup.defaults.set(try? JSONEncoder().encode(snapshot), forKey: AppGroup.recoveryStatusKey)
        #if DEBUG
        if isAmnezia {
            AppGroup.defaults.set(diagnosticAmneziaState(includeProfile: false), forKey: "diagnosticAmneziaRecoveryState.v1")
        }
        #endif
    }

    #if DEBUG
    @MainActor private func diagnosticAmneziaState(includeProfile: Bool) -> Data? {
        var state: [String: Any] = [
            "providerProcessID": Int(getpid()), "routesReleased": amneziaRoutesReleased,
            "holding": diagnosticAmneziaRecoveryHold, "phase": snapshot.phase.rawValue,
            "routesReleaseCount": diagnosticAmneziaReleaseCount,
            "settingsRestoreCount": diagnosticAmneziaRestoreCount]
        if includeProfile { state["profileID"] = profileID }
        return try? JSONSerialization.data(withJSONObject: state)
    }
    #endif

    // Display-only request through the running proxy. No fallback, health checks or repair.
    @MainActor private func measureLatency() async -> Int? {
        guard let port = latencyPort else { return nil }
        let token = generation
        let pending = latencyTask ?? (id: UUID(), task: Task {
            await ForwardedProbe.measure(port: port, request: HTTPProbeRequest.realDelay,
                                         timeout: HTTPProbeRequest.realDelayTimeout)
        })
        latencyTask = pending
        let result = await pending.task.value
        if latencyTask?.id == pending.id { latencyTask = nil }
        return valid(token) && !pending.task.isCancelled ? result : nil
    }

    @MainActor private func measureRoute(deadline: TimeInterval? = nil, transportOnly: Bool = false) async -> Int? {
        if let routeProbeTask {
            let token = generation, identifier = routeProbeID, revision = physicalPathRevision
            let latency = await routeProbeTask.value
            return valid(token) && physicalPathRevision == revision && routeProbeID == identifier ? latency : nil
        }
        guard let port = probePort, let request = probeRequest else { return nil }
        let token = generation, revision = physicalPathRevision
        let identifier = UUID(); routeProbeID = identifier
        let fallbackPort = fallbackProbePort, fallbackRequest = fallbackProbeRequest
        let task = Task<Int?, Never> { @MainActor in
            func remaining(_ maximum: TimeInterval) -> TimeInterval {
                min(maximum, max(0, (deadline ?? .greatestFiniteMagnitude) - ProcessInfo.processInfo.systemUptime))
            }
            self.systemRouteFailed = false
            guard self.bridge?.forwardingFailure == nil, remaining(ConnectionDropPolicy.probeTimeout) > 0 else { return nil }
            let current = { self.valid(token) && self.physicalPathRevision == revision }
            let needsPacketCheck = !transportOnly &&
                (self.isTelemost || self.isAmnezia || (self.automationPolicy.isTURNProxy && self.isPlainVK))
            let fallback: ((TimeInterval) async -> Int?)? = if let fallbackPort, let fallbackRequest {
                { timeout in
                    RuntimeLog.write("Primary route probe failed; checking independent endpoint")
                    return await ForwardedProbe.measure(port: fallbackPort, request: fallbackRequest, timeout: timeout)
                }
            } else { nil }
            let transportLatency: Int?
            if self.isTelemost, let fallbackPort, let fallbackRequest {
                // A slow endpoint must not consume half of the startup window.
                let timeout = min(10, max(0, remaining(16) - (deadline != nil && needsPacketCheck ? 6 : 0)))
                transportLatency = await withTaskGroup(of: Int?.self) { group in
                    group.addTask { await ForwardedProbe.measure(port: port, request: request, timeout: timeout) }
                    group.addTask { await ForwardedProbe.measure(port: fallbackPort, request: fallbackRequest, timeout: timeout) }
                    for await result in group {
                        if let result {
                            group.cancelAll()
                            return result
                        }
                    }
                    return nil
                }
            } else if self.isAmnezia {
                transportLatency = await RouteProbeSequence.measure(deadline: deadline,
                    reservedAfter: needsPacketCheck ? 6 : 0, now: { ProcessInfo.processInfo.systemUptime },
                    isCurrent: current,
                    primary: { await ForwardedProbe.measure(port: port, request: request, timeout: $0) },
                    fallback: fallback)
            } else {
                // Existing TURN checks include five-second migration windows;
                // preserve their established timeout/fallback behavior.
                var latency = await ForwardedProbe.measure(port: port, request: request, timeout: remaining(ConnectionDropPolicy.probeTimeout))
                if latency == nil, current(), remaining(ConnectionDropPolicy.probeTimeout) > 0, let fallback {
                    latency = await fallback(remaining(ConnectionDropPolicy.probeTimeout))
                }
                transportLatency = latency
            }
            guard let transportLatency, self.valid(token), self.bridge?.forwardingFailure == nil else { return nil }
            // Recovery preflight runs while the system routes are released.
            // It proves the selected proxy, never a direct internet fallback.
            if transportOnly { return transportLatency }
            #if targetEnvironment(macCatalyst)
            if self.isAmnezia, self.startCompletion == nil, #available(macCatalyst 18.0, *) {
                guard let interface = self.virtualInterface else {
                    self.systemRouteFailed = true
                    RuntimeLog.write("Amnezia system VPN interface is unavailable")
                    return nil
                }
                let systemFallback = HTTPProbeRequest(HTTPProbeRequest.systemFallbackURL, expectedStatusCode: 200)
                let fallback: ((TimeInterval) async -> Int?)? = if let systemFallback, request.host != systemFallback.host {
                    { await ForwardedProbe.measureThroughInterface(interface, request: systemFallback, timeout: $0) }
                } else { nil }
                let latency = await RouteProbeSequence.measure(deadline: deadline,
                    now: { ProcessInfo.processInfo.systemUptime }, isCurrent: current,
                    primary: { await ForwardedProbe.measureThroughInterface(interface, request: request, timeout: $0) },
                    fallback: fallback)
                guard self.valid(token) else { return nil }
                self.systemRouteFailed = latency == nil || self.bridge?.forwardingFailure != nil
                if self.systemRouteFailed {
                    RuntimeLog.write("Amnezia system DNS/TCP/TLS route failed; a proxy ping cannot mark this tunnel healthy")
                    return nil
                }
                // Split rules can send this system request directly. Also
                // require the profile's own proxy above so bypassed addresses
                // cannot hide a broken Amnezia transport.
                return latency.map { max($0, transportLatency) }
            }
            #endif
            if needsPacketCheck {
                let configuredServer = self.settings.vpnDNS.first(where: { IPv4Address($0) != nil })
                guard let server = configuredServer ?? (self.isAmnezia ? nil : "1.1.1.1"),
                      let bridge = self.bridge,
                      let probe = TunnelDNSProbe(server: server) else { return nil }
                guard remaining(6) > 0 else { return nil }
                let reply = await bridge.exchangePacket(probe.packet, family: UInt32(AF_INET), timeout: remaining(6),
                                                       matching: { probe.matches($0, family: $1) })
                guard self.valid(token), let reply, probe.succeeded(reply), bridge.forwardingFailure == nil else {
                    RuntimeLog.write("Proxy responds, but the app-packet DNS path failed")
                    return nil
                }
            }
            return transportLatency
        }
        routeProbeTask = task
        let result = await task.value
        if routeProbeID == identifier { routeProbeTask = nil }
        return valid(token) && physicalPathRevision == revision && routeProbeID == identifier ? result : nil
    }

    @MainActor private func startTrafficSampling() {
        trafficTask?.cancel()
        traffic = TrafficLedger(
            uploaded: (AppGroup.defaults.object(forKey: AppGroup.uploadedBytesKey) as? NSNumber)?.uint64Value ?? 0,
            downloaded: (AppGroup.defaults.object(forKey: AppGroup.downloadedBytesKey) as? NSNumber)?.uint64Value ?? 0)
        trafficAt = Date()
        trafficTask = Task { @MainActor in
            var nextMemorySample = ProcessInfo.processInfo.systemUptime
            while !Task.isCancelled {
                do { try await Task.sleep(for: .seconds(1)) } catch { return }
                if isAmnezia, hasEstablishedConnection, networkAvailable,
                   lifecycleTask == nil, !reportedAmneziaPacketFailure, bridge?.forwardingFailure != nil {
                    // Only a concrete local packet-channel failure needs an
                    // engine replacement. Idle time and app visibility do not.
                    requestAmneziaPacketRepair()
                }
                sampleTraffic()
                let now = ProcessInfo.processInfo.systemUptime
                if now >= nextMemorySample {
                    let footprint = memoryFootprint()
                    RuntimeLog.write(String(format: "Tunnel memory footprint: %.1f MB", Double(footprint) / 1_048_576))
                    if footprint >= 40 * 1_048_576 { SwiftyXray.releaseUnusedMemory() }
                    nextMemorySample = now + 10
                }
            }
        }
    }

    @MainActor private func sampleTraffic() {
        guard let bridge else { return }
        let stats = bridge.getAndClearStats()
        let now = Date()
        traffic.record(sent: stats.sent, received: stats.received, elapsed: now.timeIntervalSince(trafficAt))
        trafficAt = now
        AppGroup.defaults.set(NSNumber(value: traffic.uploaded), forKey: AppGroup.uploadedBytesKey)
        AppGroup.defaults.set(NSNumber(value: traffic.downloaded), forKey: AppGroup.downloadedBytesKey)
    }

    @MainActor private func stopRuntime(preserveDirectTraffic: Bool = false) {
        turnCaptchaTask?.cancel(); turnCaptchaTask = nil; blockedTURNChallengeID = nil
        turnCaptchaVerificationTask?.cancel(); turnCaptchaVerificationTask = nil
        turnCaptchaExpiryID = UUID()
        turnCaptchaExpiryTask?.cancel(); turnCaptchaExpiryTask = nil; awaitingTURNChallengeResult = false
        cancelTURNMigration()
        latencyTask?.task.cancel(); latencyTask = nil; latencyPort = nil
        routeProbeTask?.cancel(); routeProbeTask = nil; routeProbeID = UUID()
        if preserveDirectTraffic, coreRunning, settings.splitTunneling?.mode != .disabled,
           settings.splitTunneling != nil, bridge?.forwardingFailure == nil {
            NativeTURNBridge.stop()
            return
        }
        coreRunning = false
        trafficTask?.cancel(); trafficTask = nil
        sampleTraffic()
        probePort = nil; probeRequest = nil
        fallbackProbePort = nil; fallbackProbeRequest = nil
        routeProbeTask?.cancel(); routeProbeTask = nil; routeProbeID = UUID()
        bridge?.stop()
        NativeTURNBridge.stop()
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        Task { @MainActor in
            stopped = true; generation = UUID()
            let stopToken = generation
            resetFullTunnel()
            cancelAmneziaRepair()
            hasEstablishedConnection = false
            lifecycleTask?.cancel(); lifecycleTask = nil
            monitorTask?.cancel(); monitorTask = nil
            pathMonitor?.cancel(); pathMonitor = nil
            stopRuntime(); NativeTURNBridge.resetTransportPreference()
            PhysicalDNSRuntime.stop(); physicalDNSPort = 0
            accessTask?.cancel(); accessTask = nil
            reasserting = false
            // Queue behind any in-flight route installation. Its late callback
            // must finish (and be cleared) before this stop is acknowledged.
            try? await applyNetworkSettings(nil, token: stopToken)
            guard generation == stopToken, stopped else { completionHandler(); return }
            finishStart(makeError("Connection cancelled."))
            publish(.disconnected, "VPN is disconnected")
            AppGroup.defaults.removeObject(forKey: AppGroup.turnStatusKey)
            telemostRecovery = nil
            RuntimeLog.write("Packet tunnel stopped, reason \(reason.rawValue)")
            completionHandler()
        }
    }

    @MainActor private func cancelAmneziaRepair() {
        amneziaRepairID = UUID()
        amneziaRepairTask?.cancel(); amneziaRepairTask = nil
    }

    @MainActor private var amneziaSessionIsCurrent: Bool {
        !stopped && recoveryProfileIsSelected && (try? PanelAccess.require(panelAccess)) != nil
    }

    @MainActor private func refreshAmneziaTransport() {
        guard isAmnezia, coreRunning, hasEstablishedConnection, !stopped,
              lifecycleTask == nil, amneziaRepairTask == nil else { return }
        // Wake/path changes only rebind sockets; a watchdog requires two
        // failed route checks before replacing an otherwise healthy engine.
        if !SwiftyXray.refreshAmneziaSockets() {
            RuntimeLog.write("Amnezia socket refresh was not queued")
        }
    }

    @MainActor private func startAmneziaMonitoring() {
        guard hasEstablishedConnection, lifecycleTask == nil, amneziaRepairTask == nil else { return }
        let token = generation
        monitorTask = Task { @MainActor in
            var schedule = BackgroundProbeSchedule(now: ProcessInfo.processInfo.systemUptime)
            var health = AmneziaHealthPolicy()
            while valid(token) {
                do { try await Task.sleep(for: .seconds(1)) } catch { return }
                guard valid(token), amneziaRepairTask == nil else { return }
                guard amneziaSessionIsCurrent else {
                    stopRuntime()
                    cancelTunnelWithError(nil)
                    return
                }
                let now = ProcessInfo.processInfo.systemUptime
                let offlineExpired = health.observeNetwork(available: networkAvailable, revision: physicalPathRevision, now: now)
                if bridge?.forwardingFailure != nil {
                    requestAmneziaPacketRepair(); return
                }
                if !networkAvailable {
                    if offlineExpired { beginAmneziaRecovery(reason: "Waiting for internet"); return }
                    continue
                }
                guard networkChanged || schedule.isDue(now: now, interval: health.failures > 0 ? 5 : 30) else { continue }
                networkChanged = false
                let revision = physicalPathRevision
                let latency = await measureRoute(deadline: now + AmneziaRecoveryCoordinator.attemptTimeout)
                guard valid(token), amneziaSessionIsCurrent, amneziaRepairTask == nil else { return }
                guard networkAvailable, revision == physicalPathRevision else {
                    _ = health.observeNetwork(available: networkAvailable, revision: physicalPathRevision,
                                              now: ProcessInfo.processInfo.systemUptime)
                    continue
                }
                schedule.completed(at: ProcessInfo.processInfo.systemUptime)
                if health.recordProbe(succeeded: latency != nil, revision: revision) {
                    beginAmneziaRecovery(reason: "Restoring Amnezia data transfer")
                    return
                }
            }
        }
    }

    @MainActor private func requestAmneziaPacketRepair() {
        guard bridge?.forwardingFailure != nil else { return }
        beginAmneziaRecovery(reason: "Restoring VPN packet delivery", packetChannelFailed: true)
    }

    @MainActor private func beginAmneziaRecovery(reason: String, packetChannelFailed: Bool = false) {
        guard isAmnezia, hasEstablishedConnection, amneziaSessionIsCurrent,
              lifecycleTask == nil, amneziaRepairTask == nil else { return }
        monitorTask?.cancel(); monitorTask = nil
        routeProbeTask?.cancel(); routeProbeTask = nil; routeProbeID = UUID()
        reportedAmneziaPacketFailure = packetChannelFailed
        let token = generation, identifier = UUID()
        amneziaRepairID = identifier
        snapshot.latencyMilliseconds = nil
        RuntimeLog.write(reason)
        publish(.verifying, "Restoring VPN…")
        amneziaRepairTask = Task { @MainActor in
            defer {
                if amneziaRepairID == identifier {
                    amneziaRepairTask = nil
                    reasserting = false
                    if valid(token), amneziaSessionIsCurrent, snapshot.phase == .connected { startMonitoring() }
                }
            }
            let current = { self.valid(token) && self.amneziaRepairID == identifier && self.amneziaSessionIsCurrent }
            do {
                let latency = try await AmneziaRecoveryCoordinator.run(.init(
                    isCurrent: current,
                    networkAvailable: { self.networkAvailable },
                    pathRevision: { self.physicalPathRevision },
                    now: { ProcessInfo.processInfo.systemUptime },
                    pause: { try await Task.sleep(for: .seconds($0)) },
                    softRepair: { _ = SwiftyXray.refreshAmneziaSockets() },
                    rebuild: {
                        guard current() else { throw CancellationError() }
                        try PanelAccess.require(self.panelAccess)
                        self.stopRuntime()
                        try await self.startRuntime(token: token)
                        guard current() else { throw CancellationError() }
                    },
                    release: {
                        guard current() else { throw CancellationError() }
                        // Release system traffic before native teardown, which
                        // may need to wait for an old socket worker to finish.
                        try await self.applyNetworkSettings(nil, token: token)
                        guard current() else { throw CancellationError() }
                        self.amneziaRoutesReleased = true
                        self.reasserting = false
                        #if DEBUG
                        self.diagnosticAmneziaReleaseCount += 1
                        #endif
                        RuntimeLog.write("Amnezia VPN routes and DNS cleared; ordinary internet is available during background recovery")
                        self.publish(.retryWait, "Retrying VPN…")
                        self.stopRuntime()
                        PhysicalDNSRuntime.stop(); self.physicalDNSPort = 0
                    },
                    restore: {
                        guard current() else { throw CancellationError() }
                        try await self.setNetworkSettings()
                        guard current() else { throw CancellationError() }
                        self.amneziaRoutesReleased = false
                        #if DEBUG
                        self.diagnosticAmneziaRestoreCount += 1
                        #endif
                    },
                    verify: { deadline, transportOnly in
                        #if DEBUG
                        if self.diagnosticAmneziaRecoveryHold { return nil }
                        #endif
                        return await self.measureRoute(deadline: deadline, transportOnly: transportOnly)
                    },
                    update: { stage, attempt in
                        // The existing x/y attempt display belongs to TURN's
                        // bounded bursts. Amnezia retries have no terminal count.
                        self.snapshot.attempt = 0
                        switch stage {
                        case .repairing:
                            RuntimeLog.write("Amnezia recovery attempt \(attempt + 1); routes released=\(self.amneziaRoutesReleased)")
                            self.publish(.verifying, self.amneziaRoutesReleased
                                ? "Retrying VPN…" : "Restoring VPN…")
                        case .waitingForNetwork:
                            self.publish(.waitingForNetwork, "Waiting for network…")
                        case .standby:
                            self.publish(.retryWait, "Retrying VPN…")
                        case .restoring:
                            self.publish(.verifying, "Verifying VPN…")
                        }
                    }), packetChannelFailed: packetChannelFailed)
                guard current() else { throw CancellationError() }
                reportedAmneziaPacketFailure = false
                amneziaRoutesReleased = false
                snapshot.latencyMilliseconds = latency
                publish(.connected, "Connected")
            } catch {
                guard generation == token, amneziaRepairID == identifier, !stopped else { return }
                // Cancellation after profile replacement/access revocation is
                // terminal for this old session. A failed clear must also stop
                // the provider, never leave a dead VPN during retry backoff.
                stopRuntime()
                reasserting = false
                publish(.disconnected, error is CancellationError
                    ? "VPN connection cancelled" : "VPN recovery stopped: " + error.localizedDescription)
                cancelTunnelWithError(error is CancellationError ? nil : error)
            }
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        // The OS owns system sleep. Keep the tunnel, keys and status intact.
        completionHandler()
    }

    override func wake() {
        Task { @MainActor in
            guard !stopped else { return }
            if isAmnezia, coreRunning {
                refreshAmneziaTransport()
                return
            }
            if !isTelemost, NativeTURNBridge.supportsConnectionResume, coreRunning, hasEstablishedConnection, lifecycleTask == nil {
                migrateResumableTURN()
                return
            }
            guard automaticRecoveryEnabled else { return }
            RuntimeLog.write("VPN provider woke; checking route independently of app")
            guard lifecycleTask == nil else { return }
            if monitorTask == nil {
                beginRecovery(reason: "Restoring the connection after sleep"); return
            }
            let token = generation
            let latency = await measureRoute()
            guard valid(token), automaticRecoveryEnabled, lifecycleTask == nil else { return }
            if let latency {
                budget.restored(); snapshot.latencyMilliseconds = latency
                publish(.connected, "Connected")
            } else { beginRecovery(reason: "Restoring the connection after sleep") }
        }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        Task { @MainActor in
            switch String(data: messageData, encoding: .utf8) {
            #if DEBUG
            case "diagnosticAmneziaRecoveryHoldAfterDelay":
                #if targetEnvironment(simulator) || targetEnvironment(macCatalyst)
                completionHandler?(nil)
                #else
                guard !stopped, isAmnezia, snapshot.phase == .connected, amneziaRepairTask == nil else {
                    completionHandler?(nil); return
                }
                let token = generation
                Task { @MainActor in
                    do { try await Task.sleep(for: .seconds(10)) } catch { return }
                    guard valid(token), amneziaSessionIsCurrent, amneziaRepairTask == nil else { return }
                    diagnosticAmneziaRecoveryHold = true
                    bridge?.simulatePacketReaderFailure()
                    beginAmneziaRecovery(reason: "Checking background recovery", packetChannelFailed: true)
                }
                completionHandler?(Data("ok".utf8))
                #endif
            case "diagnosticAmneziaRecoveryReleaseAfterDelay":
                #if targetEnvironment(simulator) || targetEnvironment(macCatalyst)
                completionHandler?(nil)
                #else
                guard !stopped, isAmnezia else { completionHandler?(nil); return }
                let token = generation
                Task { @MainActor in
                    do { try await Task.sleep(for: .seconds(45)) } catch { return }
                    guard valid(token), amneziaSessionIsCurrent, diagnosticAmneziaRecoveryHold else { return }
                    diagnosticAmneziaRecoveryHold = false
                    physicalPathRevision &+= 1
                }
                completionHandler?(Data("ok".utf8))
                #endif
            case "diagnosticAmneziaRecoveryRelease":
                #if targetEnvironment(simulator) || targetEnvironment(macCatalyst)
                completionHandler?(nil)
                #else
                guard !stopped, isAmnezia, diagnosticAmneziaRecoveryHold else { completionHandler?(nil); return }
                diagnosticAmneziaRecoveryHold = false
                physicalPathRevision &+= 1
                completionHandler?(Data("ok".utf8))
                #endif
            case "diagnosticAmneziaRecoveryState":
                completionHandler?(diagnosticAmneziaState(includeProfile: true))
            case "diagnosticAmneziaSoftRebindAfterDelay":
                guard !stopped, isAmnezia, coreRunning, snapshot.phase == .connected else {
                    completionHandler?(nil); return
                }
                let token = generation
                Task { @MainActor in
                    do { try await Task.sleep(for: .seconds(5)) } catch { return }
                    guard valid(token), isAmnezia, coreRunning else { return }
                    let before = SwiftyXray.amneziaHealth()?.bindRevision.map(String.init) ?? "unavailable"
                    let accepted = SwiftyXray.refreshAmneziaSockets()
                    RuntimeLog.write("DIAGNOSTIC Amnezia socket refresh queued=\(accepted) bindRevisionBefore=\(before)")
                    do { try await Task.sleep(for: .seconds(1)) } catch { return }
                    guard valid(token), isAmnezia, coreRunning else { return }
                    let after = SwiftyXray.amneziaHealth()?.bindRevision.map(String.init) ?? "unavailable"
                    RuntimeLog.write("DIAGNOSTIC Amnezia bindRevisionAfter=\(after)")
                }
                completionHandler?(Data("ok".utf8))
            case "diagnosticPacketFlowDropAfterDelay":
                guard !stopped, isAmnezia, snapshot.phase == .connected else {
                    completionHandler?(nil); return
                }
                let token = generation
                RuntimeLog.write("DIAGNOSTIC Amnezia packet-channel drop scheduled")
                Task { @MainActor in
                    do { try await Task.sleep(for: .seconds(10)) } catch { return }
                    guard valid(token) else { return }
                    RuntimeLog.write("DIAGNOSTIC breaking only the packet reader; local proxy remains running")
                    bridge?.simulatePacketReaderFailure()
                }
                completionHandler?(Data("ok".utf8))
            case "diagnosticTransportDropAfterDelay":
                guard !stopped, snapshot.phase == .connected, automaticRecoveryEnabled else {
                    completionHandler?(nil); return
                }
                let token = generation
                RuntimeLog.write("DIAGNOSTIC background transport drop scheduled")
                Task { @MainActor in
                    do { try await Task.sleep(for: .seconds(10)) } catch { return }
                    guard valid(token), automaticRecoveryEnabled else { return }
                    RuntimeLog.write("DIAGNOSTIC inducing transport drop; app is not needed for recovery")
                    NativeTURNBridge.stop()
                }
                completionHandler?(Data("ok".utf8))
            #endif
            case "fullTunnelOn", "fullTunnelOff":
                completionHandler?(await setTemporaryFullTunnel(String(data: messageData, encoding: .utf8) == "fullTunnelOn"))
            case "appResumed":
                // Compatibility with older app processes: opening a window
                // never changes or gates an already connected tunnel.
                completionHandler?(Data("ok".utf8))
            case "settingsChanged":
                let wasMonitoring = monitorTask != nil
                monitorTask?.cancel(); monitorTask = nil
                if wasMonitoring {
                    routeProbeTask?.cancel(); routeProbeTask = nil; routeProbeID = UUID()
                }
                if !automaticRecoveryEnabled && reasserting && recoveryIsAutomatic && lifecycleTask != nil {
                    lifecycleTask?.cancel(); lifecycleTask = nil
                    generation = UUID()
                    startAccessMonitoring(token: generation)
                    startPathMonitor()
                    snapshot.latencyMilliseconds = nil
                    publish(.failed, "Connection unavailable. Automatic reconnection is disabled.")
                    reasserting = false
                } else if lifecycleTask == nil, turnMigrationTask == nil { startMonitoring() }
                completionHandler?(Data("ok".utf8))
            case "turnStatus": completionHandler?(currentTURNStatusData())
            case "recoveryStatus": completionHandler?(try? JSONEncoder().encode(snapshot))
            case "retry":
                beginRecovery(reason: "Reconnection requested", manual: true)
                completionHandler?(Data("ok".utf8))
            case "latency":
                guard !stopped, lifecycleTask == nil, snapshot.phase == .connected else { completionHandler?(nil); return }
                let token = generation
                let latency = await measureLatency()
                guard valid(token), lifecycleTask == nil, snapshot.phase == .connected else { completionHandler?(nil); return }
                completionHandler?(try? JSONSerialization.data(withJSONObject: ["latency": latency ?? -1, "profileID": profileID]))
            case "probe":
                guard !stopped, lifecycleTask == nil, snapshot.phase == .connected else { completionHandler?(nil); return }
                let token = generation
                let latency = await measureRoute()
                guard valid(token) else { completionHandler?(nil); return }
                snapshot.latencyMilliseconds = latency
                if latency != nil { publish(.connected, "Connected") }
                completionHandler?(try? JSONSerialization.data(withJSONObject: ["latency": latency ?? -1, "profileID": profileID]))
            case "stats":
                completionHandler?(try? JSONSerialization.data(withJSONObject: [
                    "uploaded": traffic.uploaded, "downloaded": traffic.downloaded,
                    "uploadSpeed": traffic.uploadSpeed, "downloadSpeed": traffic.downloadSpeed]))
            default: completionHandler?(nil)
            }
        }
    }

    @MainActor private func setNetworkSettings() async throws {
        try await applyNetworkSettings(makeNetworkSettings(mtu: mtu), token: generation)
    }

    /// MainActor alone cannot serialize async settings callbacks. Queue every
    /// installation/clear, including Stop, and undo a late obsolete install
    /// before allowing the next operation to run.
    @MainActor private func applyNetworkSettings(_ settings: NEPacketTunnelNetworkSettings?, token: UUID) async throws {
        let previous = networkSettingsTask
        let operation = Task { @MainActor in
            _ = try? await previous?.value
            guard self.generation == token else { throw CancellationError() }
            if settings != nil {
                guard self.valid(token), !self.isAmnezia || self.amneziaSessionIsCurrent else { throw CancellationError() }
            }
            try await self.writeNetworkSettings(settings)
            if settings != nil, !self.valid(token) || (self.isAmnezia && !self.amneziaSessionIsCurrent) {
                try await self.writeNetworkSettings(nil)
                throw CancellationError()
            }
        }
        networkSettingsTask = operation
        try await operation.value
    }

    @MainActor private func writeNetworkSettings(_ settings: NEPacketTunnelNetworkSettings?) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            setTunnelNetworkSettings(settings) { error in
                if let error { continuation.resume(throwing: error) } else { continuation.resume() }
            }
        }
    }

    @MainActor private func makeNetworkSettings(mtu: Int) -> NEPacketTunnelNetworkSettings {
        let appSettings = settings
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        let ipv4 = NEIPv4Settings(addresses: ["198.18.0.1"], subnetMasks: ["255.254.0.0"])
        ipv4.includedRoutes = [.default()]; settings.ipv4Settings = ipv4
        // Capture both families; Xray blocks IPv6 when it is disabled in settings.
        let ipv6 = NEIPv6Settings(addresses: ["fdfe:dcba:9876::1"], networkPrefixLengths: [64])
        ipv6.includedRoutes = [NEIPv6Route.default()]
        settings.ipv6Settings = ipv6
        let servers = appSettings.vpnDNS.filter { IPv4Address($0) != nil || IPv6Address($0) != nil }
        let dns = NEDNSSettings(servers: servers.isEmpty ? ["1.1.1.1"] : servers)
        dns.matchDomains = [""]
        dns.matchDomainsNoSearch = true
        settings.dnsSettings = dns
        settings.mtu = NSNumber(value: min(max(mtu, 1280), 1500))
        return settings
    }

    private func geoDataDirectory() -> URL {
        if let shared = try? GeoDataStore.directory() { return shared }
        return Bundle.main.resourceURL ?? Bundle.main.bundleURL
    }

    private func makeError(_ message: String) -> NSError {
        NSError(domain: "com.kindlyvpn.ios.PacketTunnel", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }

    private func memoryFootprint() -> UInt64 {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
        let result = withUnsafeMutablePointer(to: &info) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        return result == KERN_SUCCESS ? info.phys_footprint : 0
    }
}
