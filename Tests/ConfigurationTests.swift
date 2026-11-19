import XCTest
import SwiftyXrayKit
import Network
import NetworkExtension
import SwiftUI
import WebKit
@testable import TnDtun

final class ConfigurationTests: XCTestCase {
    @MainActor func testResumableRelayRepairPreservesHelperAndCancelsBeforeFallback() async throws {
        var events: [String] = []
        let latency = try await TURNRelayRepair.run(isCurrent: { true },
            resume: { events.append("resume-verified"); return 23 },
            stop: { events.append("stop") }, prepare: {}, start: {}, waitForReady: {}, verify: { 99 })
        XCTAssertEqual(latency, 23)
        XCTAssertEqual(events, ["resume-verified"])
        events.removeAll()
        var current = true
        do {
            _ = try await TURNRelayRepair.run(isCurrent: { current },
                resume: { current = false; return nil }, stop: { events.append("stop") },
                prepare: {}, start: {}, waitForReady: {}, verify: { 99 })
            XCTFail("An obsolete soft repair started destructive fallback")
        } catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertTrue(events.isEmpty)
        _ = try await TURNRelayRepair.run(isCurrent: { true }, resume: { nil },
            stop: { events.append("stop") }, prepare: { events.append("prepare") },
            start: { events.append("start") }, waitForReady: {}, verify: { 99 })
        XCTAssertEqual(events, ["stop", "prepare", "start"])
    }

    func testTURNFallbackVerificationAlwaysRequiresHTTPS() throws {
        let legacy = try XCTUnwrap(HTTPProbeRequest.turnFallback("http://example.test/health"))
        XCTAssertTrue(legacy.tls)
        XCTAssertEqual(legacy.host, "www.apple.com")
        XCTAssertEqual(legacy.expectedStatusCode, 200)
        let configured = try XCTUnwrap(HTTPProbeRequest.turnFallback("https://health.example.test/check"))
        XCTAssertTrue(configured.tls)
        XCTAssertEqual(configured.host, "health.example.test")
    }

    func testTURNRepairRetainsTCPUntilExplicitStopOrNewConnection() {
        var choice = TURNTransportPreference()
        choice.failed(transport: "udp", previouslyConnected: false, networkSwitch: false)
        XCTAssertFalse(choice.prefersTCP)
        choice.failed(transport: "udp", previouslyConnected: true, networkSwitch: true)
        XCTAssertFalse(choice.prefersTCP)
        choice.failed(transport: "udp", previouslyConnected: true, networkSwitch: false)
        XCTAssertTrue(choice.prefersTCP)
        choice.failed(transport: "udp", previouslyConnected: true, networkSwitch: true)
        XCTAssertTrue(choice.prefersTCP)
        choice.observe(transport: nil)
        XCTAssertTrue(choice.prefersTCP)
        choice.reset()
        XCTAssertFalse(choice.prefersTCP)
        choice.observe(transport: "tcp") // Native initial UDP fallback is sticky too.
        XCTAssertTrue(choice.prefersTCP)
    }

    @MainActor func testRelayRepairCannotStartHelperAfterStopProfileOrNetworkChange() async {
        for invalidation in ["Stop", "profile", "network"] {
            var current = true
            var events: [String] = []
            do {
                _ = try await TURNRelayRepair.run(isCurrent: { current }, stop: { events.append("stop") },
                    prepare: { events.append(invalidation); current = false },
                    start: { events.append("start") }, waitForReady: {}, verify: { 1 })
                XCTFail("Obsolete relay repair succeeded")
            } catch { XCTAssertTrue(error is CancellationError) }
            XCTAssertEqual(events, ["stop", invalidation], "No stale helper may bind the listener")
        }
    }

    @MainActor func testRelayRepairRejectsLateReadyAfterCancellationAndRequiresFreshVerification() async {
        let waiting = expectation(description: "Helper started and waiting for readiness")
        var resume: CheckedContinuation<Void, Never>?
        var current = true
        var checks = 0
        let task = Task { @MainActor in
            try await TURNRelayRepair.run(isCurrent: { current }, stop: {}, prepare: {}, start: {},
                waitForReady: {
                    await withCheckedContinuation { continuation in resume = continuation; waiting.fulfill() }
                }, verify: { checks += 1; return 1 })
        }
        await fulfillment(of: [waiting], timeout: 2)
        current = false; task.cancel(); resume?.resume()
        do { _ = try await task.value; XCTFail("Cancelled repair accepted old readiness") }
        catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertEqual(checks, 0)
        do {
            _ = try await TURNRelayRepair.run(isCurrent: { true }, stop: {}, prepare: {}, start: {},
                waitForReady: {}, verify: { nil })
            XCTFail("Readiness alone cannot mark TURN Connected")
        } catch { XCTAssertTrue(error is TURNRelayRepair.VerificationFailure) }
        current = true
        do {
            _ = try await TURNRelayRepair.run(isCurrent: { current }, stop: {}, prepare: {}, start: {},
                waitForReady: {}, verify: { current = false; return 42 })
            XCTFail("A late successful probe revived an obsolete repair")
        } catch { XCTAssertTrue(error is CancellationError) }
        do {
            let latency = try await TURNRelayRepair.run(isCurrent: { true }, stop: {}, prepare: {}, start: {},
                waitForReady: {}, verify: { 42 })
            XCTAssertEqual(latency, 42)
        } catch { XCTFail(error.localizedDescription) }
    }

    func testTURNRestoresOriginalDNSAndUDPInternetRouting() throws {
        var value = turn(); value.vlessID = "9f774dc1-395b-4397-890a-123456789abc"
        var settings = AppSettings(); settings.routingMode = .global
        let json = XrayConfigurationBuilder.build(profile: try value.validated(forConnection: true).profile, settings: settings)
        let root = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
        let rules = try XCTUnwrap((root["routing"] as? [String: Any])?["rules"] as? [[String: Any]])
        XCTAssertFalse(rules.contains { $0["network"] as? String == "udp" && $0["port"] as? String == "443" })
        XCTAssertEqual(rules.first?["port"] as? String, "53")
        XCTAssertEqual(rules.first?["outboundTag"] as? String, "kindly-dns")
        XCTAssertEqual(rules.last?["network"] as? String, "tcp,udp")
        XCTAssertEqual(rules.last?["outboundTag"] as? String, "proxy")
        let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".json")
        defer { try? FileManager.default.removeItem(at: file) }
        try Data(json.utf8).write(to: file)
        try SwiftyXray.testConfiguration(dataDir: Bundle.main.resourceURL!.path, configPath: file.path)
    }

    func testSavedTURNMigrationRemovesOnlyExperimentalQUICRule() throws {
        let legacy: [String: Any] = ["type": "field", "inboundTag": ["in_proxy", "kindly-socks"], "network": "udp", "port": "443", "outboundTag": "block"]
        let userRule: [String: Any] = ["type": "field", "network": "udp", "port": "443", "outboundTag": "block", "domain": ["example.com"]]
        let original: [String: Any] = [
            "inbounds": [["protocol": "tun", "tag": "in_proxy"]],
            "routing": ["domainStrategy": "IPIfNonMatch", "rules": [
                legacy, userRule,
                ["type": "field", "port": "53", "outboundTag": "kindly-dns"],
                ["type": "field", "network": "tcp,udp", "outboundTag": "proxy"],
            ]],
        ]
        var root = original
        for _ in 0..<3 {
            root = TunnelConfiguration.applying(to: root, settings: AppSettings(), isTURN: true, restoreTURNRouting: true)
        }
        let rules = try XCTUnwrap((root["routing"] as? [String: Any])?["rules"] as? [[String: Any]])
        XCTAssertEqual(rules.count, 3)
        XCTAssertEqual(rules[0]["domain"] as? [String], ["example.com"])
        XCTAssertEqual(rules[1]["outboundTag"] as? String, "kindly-dns")
        XCTAssertEqual(rules[2]["outboundTag"] as? String, "proxy")
        let untouched = TunnelConfiguration.applying(to: original, settings: AppSettings(), isTURN: true)
        XCTAssertEqual(((untouched["routing"] as? [String: Any])?["rules"] as? [[String: Any]])?.count, 4)
    }

    @MainActor func testDeviceTURNVideoDiagnostics() async throws {
        #if targetEnvironment(simulator)
        throw XCTSkip("Video diagnostics requires the physical iPad and its saved TURN profile.")
        #else
        guard ProcessInfo.processInfo.environment["SIMPLE_VIDEO_DIAGNOSTICS"] == "1" else {
            throw XCTSkip("Opt in with SIMPLE_VIDEO_DIAGNOSTICS=1; this reconnects the saved TURN profile.")
        }
        let store = SimpleStore()
        let configuration = try XCTUnwrap(store.configurations.first { $0.mode == .turn && (try? $0.validated(forConnection: true)) != nil })
        let runtime = AppStore()
        runtime.applyAutomation(autoCaptcha: store.autoCaptcha, autoRecovery: store.autoRecovery)
        try runtime.prepare(configuration)
        runtime.settings.logLevel = "info"
        runtime.save()
        defer {
            runtime.settings.logLevel = "warning"
            runtime.save()
            _ = runtime.writeActiveConfiguration()
        }
        let vpn = VPNManager()
        await vpn.load()
        await vpn.connect(using: runtime)
        let deadline = Date().addingTimeInterval(180)
        while !vpn.isConnected && Date() < deadline {
            if let error = vpn.lastError { XCTFail(error); return }
            try await Task.sleep(for: .seconds(1))
        }
        XCTAssertTrue(vpn.isConnected, "TURN did not become ready for video diagnostics.")
        guard vpn.isConnected else { return }
        print("TURN video diagnostics: connected; testing HTTPS endpoints")
        let configurationForRequests = URLSessionConfiguration.ephemeral
        configurationForRequests.timeoutIntervalForRequest = 25
        configurationForRequests.timeoutIntervalForResource = 35
        let session = URLSession(configuration: configurationForRequests)
        defer { session.invalidateAndCancel() }
        let baseline = vpn.downloadedBytes
        for address in ["https://1.1.1.1/cdn-cgi/trace", "https://www.gstatic.com/generate_204", "https://www.youtube.com/", "https://speed.cloudflare.com/__down?bytes=1048576", "https://redirector.googlevideo.com/report_mapping?di=no"] {
            let started = Date()
            do {
                let (data, response) = try await session.data(from: URL(string: address)!)
                print("TURN endpoint \(URL(string: address)!.host!): status=\((response as? HTTPURLResponse)?.statusCode ?? 0), bytes=\(data.count), seconds=\(Date().timeIntervalSince(started))")
                if address.contains("report_mapping") { print("TURN CDN mapping: \(String(decoding: data.prefix(512), as: UTF8.self))") }
            } catch { print("TURN endpoint \(URL(string: address)!.host!): \(error.localizedDescription)") }
        }
        for resolver in ["1.1.1.1", "8.8.8.8"] {
            let reply = await Self.diagnosticDNSReply(resolver: resolver)
            print("TURN system DNS \(resolver): \(reply)")
        }
        try await Task.sleep(for: .seconds(2))
        print("TURN captured traffic: received delta=\(vpn.downloadedBytes >= baseline ? vpn.downloadedBytes - baseline : 0) bytes")
        for entry in RuntimeLog.entries().filter({ $0.contains("[Error]") || $0.contains("[Warning]") || $0.contains("DNS") || $0.contains("googlevideo") || $0.contains("youtube") || $0.contains("cloudflare") }).suffix(80) {
            print("TURN video log: \(entry)")
        }
        #endif
    }

    private static func diagnosticDNSReply(resolver: String) async -> String {
        await withCheckedContinuation { continuation in
            let queue = DispatchQueue(label: "tndtun.dns-diagnostic")
            let connection = NWConnection(host: NWEndpoint.Host(resolver), port: 53, using: .udp)
            var finished = false
            func finish(_ value: String) {
                guard !finished else { return }
                finished = true
                connection.cancel()
                continuation.resume(returning: value)
            }
            // A/IN query with recursion requested; replies must carry this ID.
            let packet = Data([0x61,0x72,1,0,0,1,0,0,0,0,0,0,7] + Array("example".utf8) + [3] + Array("com".utf8) + [0,0,1,0,1])
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    connection.send(content: packet, completion: .contentProcessed { error in
                        if let error { finish("send failed: \(error)"); return }
                        connection.receiveMessage { data, _, _, error in
                            if let error { finish("receive failed: \(error)"); return }
                            guard let data, data.count >= 12, data[0] == 0x61, data[1] == 0x72 else { finish("invalid reply"); return }
                            finish("reply bytes=\(data.count), rcode=\(data[3] & 15), answers=\(Int(data[6]) * 256 + Int(data[7]))")
                        }
                    })
                case .failed(let error): finish("connection failed: \(error)")
                default: break
                }
            }
            queue.asyncAfter(deadline: .now() + 12) { finish("timeout") }
            connection.start(queue: queue)
        }
    }

    @MainActor func testDeviceTURNRemainsConnectedBeyondOneMinute() async throws {
        #if targetEnvironment(simulator)
        throw XCTSkip("Live TURN stability needs a signed physical device and its saved configuration.")
        #else
        guard ProcessInfo.processInfo.environment["SIMPLE_LIVE_TURN_TEST"] == "1" else {
            throw XCTSkip("Opt in with SIMPLE_LIVE_TURN_TEST=1 on a device with a working saved TURN profile.")
        }
        let store = SimpleStore()
        guard let configuration = store.configurations.first(where: { $0.mode == .turn && (try? $0.validated(forConnection: true)) != nil }) else {
            throw XCTSkip("No complete saved TURN configuration on this device.")
        }
        let runtime = AppStore()
        runtime.applyAutomation(autoCaptcha: true, autoRecovery: true)
        try runtime.prepare(configuration)
        let vpn = VPNManager()
        await vpn.load()
        if vpn.tunnelIsActive {
            vpn.disconnect()
            let stopDeadline = Date().addingTimeInterval(15)
            while vpn.tunnelIsActive && Date() < stopDeadline { try await Task.sleep(for: .seconds(1)) }
            XCTAssertFalse(vpn.tunnelIsActive, "Explicit disconnect did not stop the tunnel.")
            try await Task.sleep(for: .seconds(2))
            XCTAssertFalse(vpn.tunnelIsActive, "On-demand restarted the tunnel after explicit disconnect.")
        }
        let systemDNS = SystemDNSResolver.servers()
        for address in systemDNS { XCTAssertNoThrow(try ManagedDNSSettings.normalizeResolver(address)) }
        try store.rememberDNSServers(systemDNS)
        print("Physical network DNS capture: \(systemDNS.count) numeric endpoints")
        await vpn.connect(using: runtime)
        let startupDeadline = Date().addingTimeInterval(180)
        while (!vpn.isConnected || vpn.recovery.providerProcessID == nil) && Date() < startupDeadline {
            if let error = vpn.lastError { XCTFail(error); return }
            try await Task.sleep(for: .seconds(1))
        }
        XCTAssertTrue(vpn.isConnected, "TURN did not finish connecting on the physical device.")
        guard vpn.isConnected else { return }
        let initialProcess = try XCTUnwrap(vpn.recovery.providerProcessID)
        let observationDeadline = Date().addingTimeInterval(150)
        while Date() < observationDeadline {
            XCTAssertFalse(vpn.recoveryFailed, "Automatic recovery exhausted its attempts.")
            if vpn.recoveryFailed { return }
            XCTAssertEqual(vpn.recovery.providerProcessID, initialProcess, "The packet-tunnel process restarted during observation.")
            if vpn.recovery.providerProcessID != initialProcess { return }
            try await Task.sleep(for: .seconds(1))
        }
        let restorationDeadline = Date().addingTimeInterval(90)
        while !vpn.isConnected && Date() < restorationDeadline { try await Task.sleep(for: .seconds(1)) }
        XCTAssertTrue(vpn.isConnected, "TURN remained disconnected after the stability observation window.")
        #endif
    }

    @MainActor func testAutomationDefaultsPersistenceAndProfileSwitch() throws {
        let suite = "automation-test-" + UUID().uuidString
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let store = SimpleStore(fileURL: file, defaults: defaults)
        XCTAssertFalse(store.autoCaptcha)
        XCTAssertTrue(store.autoRecovery)
        XCTAssertEqual(store.turnCheckInterval, 30)
        store.autoCaptcha = false; store.autoRecovery = false; store.turnCheckInterval = 120
        let restored = SimpleStore(fileURL: file, defaults: defaults)
        XCTAssertFalse(restored.autoCaptcha)
        XCTAssertFalse(restored.autoRecovery)
        XCTAssertEqual(restored.turnCheckInterval, 120)
        let runtime = AppStore()
        runtime.applyAutomation(autoCaptcha: false, autoRecovery: true, turnCheckInterval: restored.turnCheckInterval)
        var profile = turn(); profile.vlessID = "9f774dc1-395b-4397-890a-123456789abc"
        try runtime.prepare(profile)
        XCTAssertFalse(runtime.turnSettings.isAutoCaptchaEnabled)
        XCTAssertTrue(runtime.settings.isAutoReconnectOnDropEnabled)
        XCTAssertTrue(runtime.settings.connectOnDemand)
        XCTAssertEqual(runtime.settings.recoveryMaxRetries, 5)
        let settings = try JSONDecoder().decode(AppSettings.self, from: XCTUnwrap(AppGroup.defaults.data(forKey: AppGroup.settingsKey)))
        XCTAssertEqual(settings.backgroundProbeInterval(turnProxy: true), 120)
        XCTAssertEqual(settings.backgroundProbeInterval(turnProxy: false), 30)
        let published = try JSONDecoder().decode(TURNSettings.self, from: XCTUnwrap(AppGroup.defaults.data(forKey: AppGroup.turnSettingsKey)))
        XCTAssertFalse(published.isAutoCaptchaEnabled)
    }

    func testOnlyTURNProxyCanUseBackgroundAutomationIncludingLegacyFlags() {
        let policies = [
            (TunnelAutomationPolicy(isTURN: true), true),
            (TunnelAutomationPolicy(isTURN: true, isDNS: true), false),
            (TunnelAutomationPolicy(isTURN: true, isManagedDNS: true), false),
            (TunnelAutomationPolicy(isTURN: false, isAmnezia: true), false),
            (TunnelAutomationPolicy(isTURN: true, isAmnezia: true), false),
            (TunnelAutomationPolicy(isTURN: false), false)
        ]
        for enabled in [false, true] {
            for demand in [false, true] {
                var settings = AppSettings()
                settings.isAutoReconnectOnDropEnabled = enabled
                settings.connectOnDemand = demand
                for (policy, turn) in policies {
                    XCTAssertEqual(policy.automaticRecoveryEnabled(settings), turn && enabled)
                    XCTAssertEqual(policy.onDemandEnabled(settings), turn && enabled && demand)
                    XCTAssertEqual(policy.permitsRecovery(manual: false, settings: settings), turn && enabled)
                    XCTAssertTrue(policy.permitsRecovery(manual: true, settings: settings))
                }
            }
        }
    }

    @MainActor func testSwitchingTURNAmneziaDNSClearsSystemRulesAndPreservesSavedSwitch() throws {
        let manager = NETunnelProviderManager()
        var settings = AppSettings()
        settings.isAutoReconnectOnDropEnabled = true
        settings.connectOnDemand = true
        var turnValue = turn()
        turnValue.vlessID = "9f774dc1-395b-4397-890a-123456789abc"
        var amnezia = turnValue.profile
        amnezia.amneziaRuntimeJSON = "{}" // No connection: inspect only the saved NE configuration.
        var split = SplitTunnelSettings()
        split.mode = .tunnelSelected
        settings.splitTunneling = split
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let saved = try encoder.encode(settings)
        for profile in [turnValue.profile, amnezia, dns().profile, turnValue.profile] {
            VPNManager.configure(manager, profile: profile, settings: settings, turnSettings: TURNSettings())
            let expected = TunnelAutomationPolicy(profile: profile).isTURNProxy
            XCTAssertEqual(manager.isOnDemandEnabled, expected)
            XCTAssertEqual(manager.onDemandRules?.count, expected ? 1 : 0)
            XCTAssertEqual(VPNManager.automationPolicy(for: manager).isTURNProxy, expected)
            let config = try XCTUnwrap(manager.protocolConfiguration as? NETunnelProviderProtocol)
            XCTAssertEqual(config.providerConfiguration?["profileId"] as? String, profile.id)
            XCTAssertFalse(config.disconnectOnSleep)
            XCTAssertEqual(try encoder.encode(settings), saved)
        }
        settings.isAutoReconnectOnDropEnabled = false
        VPNManager.configure(manager, profile: turnValue.profile, settings: settings, turnSettings: TURNSettings())
        XCTAssertFalse(manager.isOnDemandEnabled)
        XCTAssertEqual(manager.onDemandRules?.count, 0)
    }

    func testTURNBackgroundIntervalDoesNotChangeOtherTransportsAndOldSettingsDecode() throws {
        var settings = AppSettings()
        settings.recoveryCheckInterval = 60
        settings.turnCheckInterval = 15
        XCTAssertEqual(settings.backgroundProbeInterval(turnProxy: true), 15)
        XCTAssertEqual(settings.backgroundProbeInterval(turnProxy: false), 60)
        var old = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(settings)) as? [String: Any])
        old.removeValue(forKey: "turnCheckInterval")
        let migrated = try JSONDecoder().decode(AppSettings.self, from: JSONSerialization.data(withJSONObject: old))
        XCTAssertEqual(migrated.backgroundProbeInterval(turnProxy: true), 30)
        XCTAssertEqual(migrated.backgroundProbeInterval(turnProxy: false), 60)
    }

    func testBackgroundScheduleUsesLatestIntervalAndWaitsAfterSlowProbe() {
        var schedule = BackgroundProbeSchedule(now: 100)
        XCTAssertFalse(schedule.isDue(now: 114, interval: 30))
        // A saved shorter interval is effective on the next provider tick.
        XCTAssertTrue(schedule.isDue(now: 115, interval: 15))
        XCTAssertFalse(schedule.isDue(now: 130, interval: 300))
        // Both endpoint attempts finished 30 seconds later. Avoid a new probe
        // immediately after the timeout, even with the shortest interval.
        schedule.completed(at: 145)
        XCTAssertFalse(schedule.isDue(now: 159, interval: 15))
        XCTAssertTrue(schedule.isDue(now: 160, interval: 15))
        // After a prolonged sleep the provider checks without app activation.
        XCTAssertTrue(schedule.isDue(now: 500, interval: 300))
    }

    func testTURNFailedRouteCheckRecoversInOneCycleAndOtherModesKeepTwoChecks() {
        var turn = RecoveryBudget()
        XCTAssertTrue(turn.recordProbe(succeeded: false, failureThreshold: 1))
        turn.restored()
        XCTAssertFalse(turn.recordProbe(succeeded: true, failureThreshold: 1))
        var other = RecoveryBudget()
        XCTAssertFalse(other.recordProbe(succeeded: false))
        XCTAssertFalse(other.recordProbe(succeeded: true))
        XCTAssertFalse(other.recordProbe(succeeded: false))
        XCTAssertTrue(other.recordProbe(succeeded: false))
    }

    @MainActor func testDNSListNormalizesDeduplicatesAndPersists() throws {
        let suite = "dns-list-test-" + UUID().uuidString
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let store = SimpleStore(fileURL: file, defaults: defaults)
        try store.rememberDNSServers(["1.1.1.1", "1.1.1.1:53", "2001:db8::53"])
        XCTAssertEqual(store.savedDNSServers, ["1.1.1.1:53", "[2001:db8::53]:53"])
        XCTAssertThrowsError(try store.rememberDNSServers(["8.8.8.8", "not-an-address"]))
        XCTAssertEqual(store.savedDNSServers.count, 2)
        let restored = SimpleStore(fileURL: file, defaults: defaults)
        XCTAssertEqual(restored.savedDNSServers, store.savedDNSServers)
        restored.forgetDNSServer("1.1.1.1:53")
        XCTAssertEqual(SimpleStore(fileURL: file, defaults: defaults).savedDNSServers, ["[2001:db8::53]:53"])
    }

    func testRecoveryWaitsWithoutConsumingAttemptsAndResetsAfterSuccess() {
        var budget = RecoveryBudget()
        for _ in 0..<100 { XCTAssertEqual(budget.next(networkAvailable: false, maximum: 5), .waitForNetwork) }
        XCTAssertEqual(budget.attempts, 0)
        XCTAssertFalse(budget.recordProbe(succeeded: false))
        XCTAssertFalse(budget.recordProbe(succeeded: true))
        XCTAssertFalse(budget.recordProbe(succeeded: false))
        XCTAssertTrue(budget.recordProbe(succeeded: false))
        for count in 1...5 { XCTAssertEqual(budget.next(networkAvailable: true, maximum: 5), .attempt(count)) }
        XCTAssertEqual(budget.next(networkAvailable: true, maximum: 5), .exhausted)
        budget.restored()
        XCTAssertEqual(budget.next(networkAvailable: true, maximum: 5), .attempt(1))
        XCTAssertFalse(ConnectionDropPolicy.shouldReconnect(autoReconnectEnabled: true,
            unexpected: ConnectionDropPolicy.isUnexpected(connectionWasActive: true, shutdownExpected: true)))
    }

    func testRecoveryContinuesInBackgroundAfterBoundedBurst() {
        var budget = RecoveryBudget()
        for _ in 0..<3 {
            for attempt in 1...5 { XCTAssertEqual(budget.next(networkAvailable: true, maximum: 5), .attempt(attempt)) }
            XCTAssertEqual(budget.next(networkAvailable: true, maximum: 5), .exhausted)
            XCTAssertGreaterThanOrEqual(ConnectionDropPolicy.retryCooldown, 30)
            budget.resumeAfterCooldown()
            XCTAssertEqual(budget.next(networkAvailable: false, maximum: 5), .waitForNetwork)
            XCTAssertEqual(budget.attempts, 0)
        }
        budget.restored()
        XCTAssertFalse(budget.recordProbe(succeeded: false))
        XCTAssertLessThanOrEqual(ConnectionDropPolicy.transportDropGrace, 15)
    }

    func testTURNLatencyTargetMatchesAndroidAndFallbackAlwaysUsesProxy() throws {
        let primary = try XCTUnwrap(HTTPProbeRequest(HTTPProbeRequest.turnURL))
        XCTAssertEqual(primary.host, "1.1.1.1")
        XCTAssertTrue(primary.tls)
        let fallback = try XCTUnwrap(HTTPProbeRequest(HTTPProbeRequest.recoveryURL))
        var root: [String: Any] = ["routing": ["rules": [["type": "field", "network": "tcp,udp", "outboundTag": "direct"]]]]
        root = ProbeConfiguration.adding(to: root, port: 12345, request: primary)
        root = ProbeConfiguration.adding(to: root, port: 12346, request: fallback, tag: "kindly-health-fallback")
        let rules = try XCTUnwrap((root["routing"] as? [String: Any])?["rules"] as? [[String: Any]])
        XCTAssertEqual(rules[0]["inboundTag"] as? [String], ["kindly-health-fallback"])
        XCTAssertEqual(rules[0]["outboundTag"] as? String, "proxy")
        XCTAssertEqual(rules[1]["outboundTag"] as? String, "proxy")
        XCTAssertEqual(rules[2]["outboundTag"] as? String, "direct")
    }

    func testManualRealDelayEndpointAndRuleDoNotChangeHealthOrSplitRules() throws {
        let request = HTTPProbeRequest.realDelay
        XCTAssertEqual(HTTPProbeRequest.realDelayURL, "https://www.gstatic.com/generate_204")
        XCTAssertEqual(request.host, "www.gstatic.com")
        XCTAssertEqual(request.port, 443)
        XCTAssertTrue(request.tls)
        XCTAssertEqual(request.expectedStatusCode, 204)
        XCTAssertTrue(String(decoding: request.data, as: UTF8.self).hasPrefix("GET /generate_204 HTTP/1.1\r\n"))
        let health = try XCTUnwrap(HTTPProbeRequest(HTTPProbeRequest.turnURL))
        let root = ProbeConfiguration.adding(to: ["routing": ["rules": [["type": "field", "network": "tcp,udp", "outboundTag": "direct"]]]],
                                            port: 12345, request: health)
        let updated = ProbeConfiguration.adding(to: root, port: 12346, request: request, tag: "kindly-latency")
        let rules = try XCTUnwrap((updated["routing"] as? [String: Any])?["rules"] as? [[String: Any]])
        XCTAssertEqual(rules[0]["inboundTag"] as? [String], ["kindly-latency"])
        XCTAssertEqual(rules[0]["outboundTag"] as? String, "proxy")
        let originalRules = try XCTUnwrap((root["routing"] as? [String: Any])?["rules"])
        XCTAssertEqual(try JSONSerialization.data(withJSONObject: Array(rules.dropFirst()), options: .sortedKeys),
                       try JSONSerialization.data(withJSONObject: originalRules, options: .sortedKeys))
        let inbounds = try XCTUnwrap(updated["inbounds"] as? [[String: Any]])
        XCTAssertEqual(inbounds.last?["listen"] as? String, "127.0.0.1")
        XCTAssertEqual((inbounds.last?["settings"] as? [String: Any])?["address"] as? String, request.host)
    }

    func testAutomaticCaptchaFallbackStillAllowsFiveMinutesForManualChallenge() {
        XCTAssertEqual(ConnectionDropPolicy.turnReadyTimeout(captchaPending: true, autoCaptcha: true), 300)
        XCTAssertEqual(ConnectionDropPolicy.turnReadyTimeout(captchaPending: true, autoCaptcha: false), 300)
        XCTAssertEqual(ConnectionDropPolicy.turnReadyTimeout(captchaPending: false, autoCaptcha: true), 180)
    }

    @MainActor func testCaptchaHandoffSurvivesAppRecreationWithoutChangingAutomaticPreference() {
        let pending = Data(#"{"running":true,"ready":false,"transport":"udp","connected_streams":0,"captcha_required":true,"captcha_id":17,"captcha_age_ms":45000}"#.utf8)
        for vpn in [VPNManager(), VPNManager()] {
            vpn.applyTURNStatus(pending)
            XCTAssertEqual(vpn.turnCaptchaID, 17)
            XCTAssertTrue(vpn.turnCaptchaNeedsUser(automatic: true))
            vpn.applyTURNStatus(Data(#"{"running":true,"ready":false,"transport":"udp","connected_streams":0,"captcha_required":true,"captcha_id":18,"captcha_age_ms":100}"#.utf8))
            XCTAssertEqual(vpn.turnCaptchaID, 18)
            XCTAssertFalse(vpn.turnCaptchaNeedsUser(automatic: true), "A new challenge has its own automatic window")
            XCTAssertTrue(vpn.turnCaptchaNeedsUser(automatic: false))
        }
    }

    func testCaptchaAbsoluteDeadlineAndTerminalFailureAreIndependentOfReadinessWindows() {
        for age: Int64 in [45_000, 60_000, 180_000, 299_999] {
            XCTAssertTrue(TURNCaptchaPolicy.needsUser(ageMilliseconds: age, automatic: true))
            XCTAssertFalse(TURNCaptchaPolicy.expired(ageMilliseconds: age))
        }
        XCTAssertFalse(TURNCaptchaPolicy.needsUser(ageMilliseconds: 44_999, automatic: true))
        XCTAssertTrue(TURNCaptchaPolicy.expired(ageMilliseconds: 300_000))
        XCTAssertTrue(TURNCaptchaPolicy.terminalFailure("FATAL_CAPTCHA_FAILED_NO_STREAMS"))
        XCTAssertTrue(TURNCaptchaPolicy.terminalFailure("manual captcha timed out after 5m"))
        XCTAssertFalse(TURNCaptchaPolicy.terminalFailure("network unreachable"))
    }

    @MainActor func testCaptchaOnExistingLanesSurfacesOnlyWhenRouteWasBlocked() {
        let vpn = VPNManager()
        vpn.applyTURNStatus(Data(#"{"running":true,"ready":true,"transport":"udp","connected_streams":2,"captcha_required":true,"captcha_id":19,"captcha_age_ms":50000,"captcha_blocks_route":true}"#.utf8))
        XCTAssertTrue(vpn.turnCaptchaRequired)
        XCTAssertTrue(vpn.turnCaptchaNeedsUser(automatic: true))
        vpn.applyTURNStatus(Data(#"{"running":true,"ready":true,"transport":"udp","connected_streams":2,"captcha_required":false}"#.utf8))
        XCTAssertFalse(vpn.turnCaptchaRequired)
        XCTAssertFalse(vpn.turnCaptchaNeedsUser(automatic: true))
    }

    @MainActor func testManualCaptchaOnExtraLanesDoesNotBlockReadyTURN() {
        let vpn = VPNManager()
        vpn.applyTURNStatus(Data(#"{"running":true,"ready":true,"transport":"udp","connected_streams":2,"captcha_required":true}"#.utf8))
        XCTAssertTrue(vpn.turnReady)
        XCTAssertEqual(vpn.turnConnectedStreams, 2)
        XCTAssertFalse(vpn.turnCaptchaRequired)
        vpn.applyTURNStatus(Data(#"{"running":true,"ready":false,"transport":"udp","connected_streams":0,"captcha_required":true}"#.utf8))
        XCTAssertFalse(vpn.turnReady)
        XCTAssertTrue(vpn.turnCaptchaRequired)
        vpn.applyTURNStatus(Data(#"{"running":true,"ready":true,"transport":"udp","connected_streams":1,"captcha_required":false}"#.utf8))
        XCTAssertTrue(vpn.turnReady)
        XCTAssertFalse(vpn.turnCaptchaRequired)
    }

    func testTURNDefaultsAndCredentialRequirement() throws {
        var value = turn()
        let saved = try value.validated()
        XCTAssertEqual(saved.server, "203.0.113.10:56010")
        XCTAssertThrowsError(try value.validated(forConnection: true))
        value.vlessID = "9f774dc1-395b-4397-890a-123456789abc"
        let ready = try value.validated(forConnection: true)
        XCTAssertEqual(ready.profile.credential, value.vlessID)
        XCTAssertTrue(ready.profile.isTURN)
        XCTAssertFalse(ready.profile.isManagedDNS)
        XCTAssertEqual(ready.profile.id, value.id)
    }

    func testTURNRejectsInvalidLinksPortsAndWrapKeys() {
        for link in ["http://vk.com/call/join/abc", "https://example.com/call/join/abc", "https://vk.com/call/join/"] {
            var value = turn(); value.callLink = link
            XCTAssertThrowsError(try value.validated())
        }
        for address in ["", "203.0.113.10:0", "203.0.113.10:65536", "https://server.example.com", "server host:53"] {
            XCTAssertThrowsError(try SimpleConfiguration.normalizedServer(address), address)
        }
        var value = turn(); value.wrapKey = "incorrect"
        XCTAssertThrowsError(try value.validated())
    }

    func testIPv6AndExplicitPortsArePreserved() throws {
        XCTAssertEqual(try SimpleConfiguration.normalizedServer("2001:db8::1"), "[2001:db8::1]:56010")
        XCTAssertEqual(try SimpleConfiguration.normalizedServer("[2001:db8::1]:443"), "[2001:db8::1]:443")
        XCTAssertEqual(try SimpleConfiguration.normalizedServer("203.0.113.10:443"), "203.0.113.10:443")
    }

    func testDNSPoolMigratesExistingProfilesAndReachesRuntime() throws {
        let legacy = Data(#"{"domain":"tunnel.example.com","publicKey":"abababababababababababababababababababababababababababababababab"}"#.utf8)
        var restored = try JSONDecoder().decode(ManagedDNSSettings.self, from: legacy)
        XCTAssertEqual(restored.sessionCount, 4)
        for count in ManagedDNSSettings.sessionCounts {
            restored.sessionCount = count
            let saved = try JSONDecoder().decode(ManagedDNSSettings.self, from: JSONEncoder().encode(restored))
            XCTAssertEqual(saved.sessionCount, count)
            let payload = try XCTUnwrap(JSONSerialization.jsonObject(with: saved.runtimePayload()) as? [String: Any])
            let native = try XCTUnwrap(payload["managed_dns"] as? [String: Any])
            XCTAssertEqual(native["session_count"] as? Int, count)
        }
        restored.sessionCount = 16
        XCTAssertThrowsError(try restored.validated())
    }

    func testWiFiDNSOverridePreservesCarrierResolverAndMigratesOldProfiles() throws {
        let legacy = Data(#"{"resolver":"203.0.113.53:53","domain":"tunnel.example.com","publicKey":"abababababababababababababababababababababababababababababababab"}"#.utf8)
        var value = try JSONDecoder().decode(ManagedDNSSettings.self, from: legacy)
        XCTAssertFalse(value.useWiFiResolver)
        XCTAssertEqual(value.wifiResolver, "8.8.8.8")
        func nativeResolver(_ settings: ManagedDNSSettings, wifi: Bool) throws -> String? {
            let root = try XCTUnwrap(JSONSerialization.jsonObject(with: settings.runtimePayload(usingWiFi: wifi)) as? [String: Any])
            return (root["managed_dns"] as? [String: Any])?["resolver"] as? String
        }
        XCTAssertEqual(try nativeResolver(value, wifi: true), "203.0.113.53:53")
        value.useWiFiResolver = true
        XCTAssertEqual(try nativeResolver(value, wifi: true), "8.8.8.8:53")
        XCTAssertEqual(try nativeResolver(value, wifi: false), "203.0.113.53:53")
        value.wifiResolver = " [2001:4860:4860::8888]:5353 "
        let restored = try JSONDecoder().decode(ManagedDNSSettings.self, from: JSONEncoder().encode(value.validated()))
        XCTAssertTrue(restored.useWiFiResolver)
        XCTAssertEqual(try nativeResolver(restored, wifi: true), "[2001:4860:4860::8888]:5353")
        XCTAssertEqual(try nativeResolver(restored, wifi: false), "203.0.113.53:53")
        value.wifiResolver = "bad-dns"
        XCTAssertThrowsError(try value.validated())
        value.useWiFiResolver = false
        XCTAssertEqual(try nativeResolver(value, wifi: true), "203.0.113.53:53")
        XCTAssertEqual(value.resolver, "203.0.113.53:53")
    }

    @MainActor func testConnectionDNSDetectionSelectsExistingServerWithoutDuplicatesAndPersists() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let defaults = UserDefaults(suiteName: UUID().uuidString)!
        defaults.set(["203.0.113.53", "203.0.113.53:53"], forKey: "simple.savedDNSServers")
        let file = directory.appendingPathComponent("profiles.json")
        let store = SimpleStore(fileURL: file, defaults: defaults)
        let original = dns()
        try store.save(original)
        let detected = try store.applyingDetectedDNS(to: original,
            servers: ["invalid", "203.0.113.53", "203.0.113.53:53"], usingWiFi: false)
        XCTAssertEqual(detected.dns.resolver, "203.0.113.53:53")
        let repeated = try store.applyingDetectedDNS(to: detected, servers: ["203.0.113.53:53"], usingWiFi: false)
        XCTAssertEqual(repeated.dns.savedResolvers, ["203.0.113.53:53"])
        XCTAssertEqual(store.savedDNSServers, ["203.0.113.53:53"])
        let nextNetwork = try store.applyingDetectedDNS(to: repeated, servers: ["203.0.113.54"], usingWiFi: false)
        XCTAssertEqual(nextNetwork.dns.resolver, "203.0.113.54:53")
        XCTAssertEqual(store.configurations.count, 1)
        let restored = SimpleStore(fileURL: file, defaults: defaults)
        XCTAssertEqual(restored.configurations.first?.dns.resolver, "203.0.113.54:53")
        XCTAssertEqual(restored.savedDNSServers, ["203.0.113.53:53", "203.0.113.54:53"])
    }

    @MainActor func testConnectionDNSDetectionRespectsWiFiOverrideButStillUpdatesOnCellular() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = SimpleStore(fileURL: directory.appendingPathComponent("profiles.json"), defaults: UserDefaults(suiteName: UUID().uuidString)!)
        var original = dns()
        original.dns.useWiFiResolver = true
        original.dns.wifiResolver = "8.8.8.8"
        let wifi = try store.applyingDetectedDNS(to: original, servers: ["192.168.1.1"], usingWiFi: true)
        XCTAssertEqual(wifi.dns.resolver, original.dns.resolver)
        XCTAssertEqual(wifi.dns.effectiveResolver(usingWiFi: true), "8.8.8.8")
        XCTAssertTrue(store.savedDNSServers.isEmpty)
        let unknown = try store.applyingDetectedDNS(to: original, servers: ["192.168.1.1"], usingWiFi: nil)
        XCTAssertEqual(unknown.dns.resolver, original.dns.resolver)
        let cellular = try store.applyingDetectedDNS(to: original, servers: ["203.0.113.53"], usingWiFi: false)
        XCTAssertEqual(cellular.dns.resolver, "203.0.113.53:53")
        XCTAssertEqual(cellular.dns.effectiveResolver(usingWiFi: true), "8.8.8.8:53")
    }

    @MainActor func testConnectionDNSDetectionFallsBackAndLeavesTURNUnchanged() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = SimpleStore(fileURL: directory.appendingPathComponent("profiles.json"), defaults: UserDefaults(suiteName: UUID().uuidString)!)
        let original = dns()
        for servers in [[], ["bad-address"]] {
            let unchanged = try store.applyingDetectedDNS(to: original, servers: servers, usingWiFi: false)
            XCTAssertEqual(unchanged.dns.resolver, original.dns.resolver)
        }
        let wifi = try store.applyingDetectedDNS(to: original, servers: ["192.168.1.1"], usingWiFi: true)
        XCTAssertEqual(wifi.dns.resolver, "192.168.1.1:53")
        let turnProfile = turn()
        let unchangedTURN = try store.applyingDetectedDNS(to: turnProfile, servers: ["203.0.113.53"], usingWiFi: false)
        XCTAssertEqual(unchangedTURN.dns.resolver, turnProfile.dns.resolver)
        XCTAssertEqual(store.savedDNSServers, ["192.168.1.1:53"])
        var manual = original
        manual.dns.autoDetectResolver = false
        let unchangedManual = try store.applyingDetectedDNS(to: manual, servers: ["203.0.113.53"], usingWiFi: false)
        XCTAssertEqual(unchangedManual.dns.resolver, original.dns.resolver)
        XCTAssertEqual(store.savedDNSServers, ["192.168.1.1:53"])
    }

    @MainActor func testDetectedDNSRemainsUsableWhenProfileStorageCannotBeUpdated() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = root.appendingPathComponent("profiles")
        let file = directory.appendingPathComponent("profiles.json")
        let defaults = UserDefaults(suiteName: UUID().uuidString)!
        let store = SimpleStore(fileURL: file, defaults: defaults)
        let original = dns()
        try store.save(original)
        let preserved = root.appendingPathComponent("preserved")
        try FileManager.default.moveItem(at: directory, to: preserved)
        try Data("blocked".utf8).write(to: directory)
        let selected = try store.applyingDetectedDNS(to: original, servers: ["203.0.113.53"], usingWiFi: false)
        XCTAssertEqual(selected.dns.resolver, "203.0.113.53:53")
        XCTAssertNoThrow(try selected.dns.runtimePayload())
        XCTAssertEqual(store.configurations.first?.dns.resolver, original.dns.resolver)
        XCTAssertEqual(store.savedDNSServers, ["203.0.113.53:53"])
        let saved = try JSONDecoder().decode([SimpleConfiguration].self,
            from: Data(contentsOf: preserved.appendingPathComponent("profiles.json")))
        XCTAssertEqual(saved.first?.dns.resolver, original.dns.resolver)
    }

    func testDNSAutoDetectMigratesOldProfilesAndPersistsManualChoice() throws {
        let legacy = Data(#"{"resolver":"203.0.113.53:53"}"#.utf8)
        var value = try JSONDecoder().decode(ManagedDNSSettings.self, from: legacy)
        XCTAssertTrue(value.autoDetectResolver)
        value.autoDetectResolver = false
        XCTAssertFalse(try JSONDecoder().decode(ManagedDNSSettings.self, from: JSONEncoder().encode(value)).autoDetectResolver)
    }

    func testDNSRequiresCorrectPublicKeyAndSSHCredentials() throws {
        var value = dns()
        XCTAssertTrue(try value.validated(forConnection: true).profile.isManagedDNS)
        value.dns.publicKey = "abc"
        XCTAssertThrowsError(try value.validated())
        value = dns(); value.dns.tunnelType = "ssh"
        XCTAssertThrowsError(try value.validated())
        value.dns.sshUsername = "test"; value.dns.sshPassword = "test-password"
        value.dns.sshHostKey = "SHA256:example-test-fingerprint"
        XCTAssertNoThrow(try value.validated())
    }

    @MainActor func testIndependentConfigurationsSurviveEditsDeletionAndRestart() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("configurations.json")
        let defaults = UserDefaults(suiteName: UUID().uuidString)!
        let store = SimpleStore(fileURL: file, defaults: defaults)
        let first = turn(); var second = turn(); second.server = "203.0.113.20:443"
        let third = dns()
        try store.save(first); try store.save(second); try store.save(third)
        var edited = first; edited.server = "203.0.113.30"
        try store.save(edited)
        XCTAssertEqual(store.configurations.count, 3)
        XCTAssertEqual(store.configurations[1].server, "203.0.113.20:443")
        store.mode = .dns
        let restored = SimpleStore(fileURL: file, defaults: defaults)
        XCTAssertEqual(restored.mode, .dns)
        XCTAssertEqual(restored.visibleConfigurations.map(\.id), [SimpleConfiguration.builtInDNSID, third.id])
        try restored.remove(third)
        XCTAssertEqual(SimpleStore(fileURL: file, defaults: defaults).configurations.count, 2)
        XCTAssertEqual(restored.configurations[0].server, "203.0.113.30:56010")
    }

    @MainActor func testFailedWriteDoesNotCommitInMemoryAndCorruptFileIsPreserved() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("configurations.json")
        let corrupt = Data("damaged data".utf8)
        try corrupt.write(to: file)
        let store = SimpleStore(fileURL: file)
        XCTAssertNotNil(store.error)
        XCTAssertThrowsError(try store.save(turn()))
        XCTAssertTrue(store.configurations.isEmpty)
        XCTAssertEqual(try Data(contentsOf: file), corrupt)
        let blocked = directory.appendingPathComponent("blocked")
        try Data("not a directory".utf8).write(to: blocked)
        let unable = SimpleStore(fileURL: blocked.appendingPathComponent("profiles.json"))
        XCTAssertThrowsError(try unable.save(turn()))
        XCTAssertTrue(unable.configurations.isEmpty)
    }

    func testTrafficUsesElapsedTimeAndRetainsTotals() {
        var ledger = TrafficLedger(uploaded: 1_000, downloaded: 2_000)
        ledger.record(sent: 500, received: 3_000, elapsed: 2)
        XCTAssertEqual(ledger.uploaded, 1_500)
        XCTAssertEqual(ledger.downloaded, 5_000)
        XCTAssertEqual(ledger.uploadSpeed, 250)
        XCTAssertEqual(ledger.downloadSpeed, 1_500)
        ledger.record(sent: -1, received: -1, elapsed: 1)
        XCTAssertEqual(ledger.uploaded, 1_500)
        XCTAssertEqual(ledger.downloaded, 5_000)
        XCTAssertEqual(ledger.downloadSpeed, 0)
        XCTAssertEqual(TrafficDisplay.speed(1_500), "1.5 KB/s")
    }

    private func turn() -> SimpleConfiguration {
        var value = SimpleConfiguration(); value.callLink = "https://vk.com/call/join/test-call"
        value.server = "203.0.113.10"
        return value
    }
    private func dns() -> SimpleConfiguration {
        var value = SimpleConfiguration(); value.mode = .dns; value.dns.domain = "tunnel.example.com"
        value.dns.publicKey = String(repeating: "ab", count: 32)
        return value
    }
}
