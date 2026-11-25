import XCTest
import zlib
@testable import SwiftyXrayKit
import Network
import Darwin
@testable import TnDtun

final class AmneziaTests: XCTestCase {
    @MainActor func testBuiltInDNSResolvesDomainsThroughRealDNSTTWithoutSystemVPN() async throws {
        #if targetEnvironment(simulator)
        guard ProcessInfo.processInfo.environment["TNDTUN_LIVE_BUILTIN_DNS"] == "1" else { throw XCTSkip("Opt in to the public DNSTT endpoint check inside Simulator only.") }
        let value = try SimpleConfiguration.builtInDNS()
        let settings = AppSettings()
        let request = try XCTUnwrap(HTTPProbeRequest("https://www.gstatic.com/generate_204", expectedStatusCode: 204))
        let port = try XCTUnwrap(SwiftyXray.getFreePorts(1).first)
        let config = try XCTUnwrap(XrayConfigurationBuilder.probeConfiguration(profile: value.profile, settings: settings, localPort: port, request: request))
        let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".json")
        defer { try? FileManager.default.removeItem(at: file); KindlyTurnRuntime.stop() }
        let network = try await PanelPhysicalNetwork.snapshot(readSystemDNS: false)
        do {
            let raw = String(decoding: try value.dns.runtimePayload(usingWiFi: true, builtInInterface: network.interface), as: UTF8.self)
            XCTAssertEqual(KindlyTurnRuntime.start(configurationJSON: raw), 0)
            let readyDeadline = Date().addingTimeInterval(130)
            var ready = false
            while Date() < readyDeadline {
                let data = KindlyTurnRuntime.statusData()
                let status = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
                if status?["ready"] as? Bool == true { ready = true; break }
                try await Task.sleep(for: .milliseconds(250))
            }
            if ready {
                let bridge = XrayBridge(packetFlow: TestSystemPacketFlow())
                try bridge.start(config: .json(config), dataDir: Bundle.main.resourceURL!, finalConfigPath: file)
                let result = await ForwardedProbe.measure(port: port, request: request, timeout: 30)
                bridge.stop()
                if result != nil { print("Built-in DNSTT transferred a domain HTTPS request through its own physical-network DNS pool"); return }
            }
            KindlyTurnRuntime.stop()
        }
        XCTFail("Built-in DNSTT did not transfer the domain HTTPS probe")
        #else
        throw XCTSkip("Never start this diagnostic transport in the host Mac or a real-device app process.")
        #endif
    }

    func testManualStopDuringInitialLoadCancelsLaunchIntentAndLaunchIsOnceOnly() {
        var pending = AppLaunchIntent()
        pending.cancel() // Disconnect before preferences finished loading.
        XCTAssertFalse(pending.claim())
        var fresh = AppLaunchIntent()
        XCTAssertTrue(fresh.claim())
        XCTAssertFalse(fresh.claim()) // A second window/task cannot reconnect.
    }

    @MainActor func testAmneziaPacketRepairIgnoresHealthyChannelAndRepairsFailureOnce() async throws {
        var repairs = 0, checks = 0
        let healthy = try await AmneziaPacketRepair.run(isCurrent: { true }, packetChannelFailed: { false },
            repair: { repairs += 1 }, verify: { checks += 1; return nil })
        XCTAssertNil(healthy)
        XCTAssertEqual(repairs, 0); XCTAssertEqual(checks, 0)
        let recovered = try await AmneziaPacketRepair.run(isCurrent: { true }, packetChannelFailed: { true },
            repair: { repairs += 1 }, verify: { checks += 1; return 37 })
        XCTAssertEqual(recovered, 37)
        XCTAssertEqual(repairs, 1); XCTAssertEqual(checks, 1)
        repairs = 0; checks = 0
        do {
            _ = try await AmneziaPacketRepair.run(isCurrent: { true }, packetChannelFailed: { true },
                repair: { repairs += 1 }, verify: { checks += 1; return nil })
            XCTFail("Broken channel was marked healthy")
        } catch { XCTAssertTrue(error is AmneziaPacketRepair.Unavailable) }
        XCTAssertEqual(repairs, 1); XCTAssertEqual(checks, 1)
    }

    func testAmneziaNeverUsesSavedTURNAutomationAndStillAllowsManualRecovery() {
        let amnezia = TunnelAutomationPolicy(isTURN: false, isAmnezia: true)
        for enabled in [false, true] {
            var settings = AppSettings()
            settings.isAutoReconnectOnDropEnabled = enabled
            settings.connectOnDemand = true
            XCTAssertFalse(amnezia.automaticRecoveryEnabled(settings))
            XCTAssertFalse(amnezia.onDemandEnabled(settings))
            XCTAssertFalse(amnezia.permitsRecovery(manual: false, settings: settings))
            XCTAssertTrue(amnezia.permitsRecovery(manual: true, settings: settings))
        }
    }

    @MainActor func testAmneziaPacketRepairCannotReviveStoppedTunnel() async throws {
        var current = true, repairs = 0
        do {
            _ = try await AmneziaPacketRepair.run(isCurrent: { current }, packetChannelFailed: { true },
                repair: { repairs += 1; current = false },
                verify: { XCTFail("Stop must prevent late verification"); return 1 })
            XCTFail("Late repair completion revived a stopped tunnel")
        } catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertEqual(repairs, 1)
        current = true
        do {
            _ = try await AmneziaPacketRepair.run(isCurrent: { current }, packetChannelFailed: { true },
                repair: {}, verify: { current = false; return 1 })
            XCTFail("A late probe revived a stopped tunnel")
        } catch { XCTAssertTrue(error is CancellationError) }
        do {
            _ = try await AmneziaPacketRepair.run(isCurrent: { false }, packetChannelFailed: { true },
                repair: { XCTFail("Stopped tunnel started a repair") }, verify: { 1 })
            XCTFail("Stopped tunnel accepted repair")
        } catch { XCTAssertTrue(error is CancellationError) }
    }

    func testProviderRestartRequestDoesNotBreakEarlierRecoverySnapshots() throws {
        var value = TunnelRecoverySnapshot(profileID: "amnezia-profile")
        let previous = try JSONDecoder().decode(TunnelRecoverySnapshot.self, from: JSONEncoder().encode(value))
        XCTAssertNil(previous.providerRestartRequested)
        value.providerRestartRequested = true
        value.phase = .retryWait
        let requested = try JSONDecoder().decode(TunnelRecoverySnapshot.self, from: JSONEncoder().encode(value))
        XCTAssertEqual(requested.providerRestartRequested, true)
        XCTAssertEqual(requested.profileID, value.profileID)
    }

    @MainActor func testHTTPProbeReportsBlackholeAndCancellationInsteadOfLatency() async throws {
        let queue = DispatchQueue(label: "tndtun.test-system-probe")
        let listener = try NWListener(using: .tcp, on: .any)
        let ready = expectation(description: "Local HTTP fixture ready")
        let accepted = expectation(description: "Timed-out and cancelled requests reached TCP")
        accepted.expectedFulfillmentCount = 2
        let requests = expectation(description: "Exactly one HTTP request per measurement")
        requests.expectedFulfillmentCount = 4
        listener.stateUpdateHandler = { if case .ready = $0 { ready.fulfill() } }
        listener.newConnectionHandler = { connection in
            connection.start(queue: queue)
            connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { data, _, _, _ in
                guard let data else { connection.cancel(); return }
                requests.fulfill()
                if String(decoding: data, as: UTF8.self).contains("/healthy") {
                    queue.asyncAfter(deadline: .now() + 0.12) {
                        connection.send(content: Data("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".utf8),
                                        completion: .contentProcessed { _ in connection.cancel() })
                    }
                } else if String(decoding: data, as: UTF8.self).contains("/redirect") {
                    connection.send(content: Data("HTTP/1.1 302 Found\r\nLocation: /healthy\r\nContent-Length: 0\r\n\r\n".utf8),
                                    completion: .contentProcessed { _ in connection.cancel() })
                } else {
                    accepted.fulfill()
                    // A completed TCP connect without a reply is not internet access.
                    queue.asyncAfter(deadline: .now() + 1) { connection.cancel() }
                }
            }
        }
        listener.start(queue: queue)
        defer { listener.cancel() }
        await fulfillment(of: [ready], timeout: 5)
        let port = Int(try XCTUnwrap(listener.port).rawValue)
        let healthy = try XCTUnwrap(HTTPProbeRequest("http://example.com/healthy", expectedStatusCode: 204))
        let blackhole = try XCTUnwrap(HTTPProbeRequest("http://example.com/blackhole", expectedStatusCode: 204))
        let latency = await ForwardedProbe.measure(port: port, request: healthy, timeout: 2)
        XCTAssertGreaterThanOrEqual(try XCTUnwrap(latency), 110, "Measure HTTP response time, not just TCP connect")
        XCTAssertLessThan(try XCTUnwrap(latency), 1500, "Do not add the timeout or other checks")
        let redirect = try XCTUnwrap(HTTPProbeRequest("http://example.com/redirect", expectedStatusCode: 204))
        let redirected = await ForwardedProbe.measure(port: port, request: redirect, timeout: 2)
        XCTAssertNil(redirected, "Only the expected HTTP 204 is success; do not follow redirects")
        let missing = await ForwardedProbe.measure(port: port, request: blackhole, timeout: 0.15)
        XCTAssertNil(missing)
        let task = Task { await ForwardedProbe.measure(port: port, request: blackhole, timeout: 5) }
        await fulfillment(of: [accepted], timeout: 3)
        task.cancel()
        let cancelled = await task.value
        XCTAssertNil(cancelled)
        await fulfillment(of: [requests], timeout: 2)
    }

    @MainActor func testManualRealDelayUsesProxyEvenWhenSplitBypassesEverything() async throws {
        #if targetEnvironment(simulator)
        let queue = DispatchQueue(label: "tndtun.test-latency-route")
        let listener = try NWListener(using: .tcp, on: .any)
        let ready = expectation(description: "Local endpoint ready")
        listener.stateUpdateHandler = { if case .ready = $0 { ready.fulfill() } }
        listener.newConnectionHandler = { connection in
            connection.start(queue: queue)
            connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { _, _, _, _ in
                connection.send(content: Data("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".utf8),
                                completion: .contentProcessed { _ in connection.cancel() })
            }
        }
        listener.start(queue: queue)
        defer { listener.cancel() }
        await fulfillment(of: [ready], timeout: 5)
        let targetPort = Int(try XCTUnwrap(listener.port).rawValue)
        let request = try XCTUnwrap(HTTPProbeRequest("http://127.0.0.1:\(targetPort)/generate_204", expectedStatusCode: 204))
        let port = try XCTUnwrap(SwiftyXray.getFreePorts(1).first)
        let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".json")
        defer { try? SwiftyXray.stop(); try? FileManager.default.removeItem(at: file) }
        for proxyWorks in [true, false] {
            let root: [String: Any] = [
                "outbounds": [["tag": "direct", "protocol": proxyWorks ? "blackhole" : "freedom"],
                              ["tag": "proxy", "protocol": proxyWorks ? "freedom" : "blackhole"]],
                "routing": ["rules": [["type": "field", "network": "tcp,udp", "outboundTag": "direct"]]]
            ]
            let config = ProbeConfiguration.adding(to: root, port: port, request: request, tag: "kindly-latency")
            try JSONSerialization.data(withJSONObject: config).write(to: file)
            try SwiftyXray.run(dataDir: Bundle.main.resourceURL!.path, configPath: file.path)
            let latency = await ForwardedProbe.measure(port: port, request: request, timeout: 0.5)
            if proxyWorks { XCTAssertNotNil(latency, "A blocked DIRECT route must not affect the forced VPN request") }
            else { XCTAssertNil(latency, "Working DIRECT must not conceal a broken proxy") }
            try SwiftyXray.stop()
        }
        #else
        throw XCTSkip("Isolated Simulator core only; never changes the host VPN")
        #endif
    }

    func testPacketStreamReadsAndWritesPreserveFramesAcrossInterruptionsAndShortTransfers() {
        let bytes = Array(0..<48).map(UInt8.init)
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bytes.count)
        defer { buffer.deallocate() }
        var offset = 0; var reads = 0
        XCTAssertTrue(PacketStreamIO.readExactly(fd: -1, buffer: buffer, count: bytes.count) { _, destination, maximum in
            reads += 1
            if reads == 1 || reads == 5 { errno = EINTR; return -1 }
            let count = min(maximum, 3)
            for index in 0..<count { destination.storeBytes(of: bytes[offset + index], toByteOffset: index, as: UInt8.self) }
            offset += count
            return count
        })
        XCTAssertEqual(Array(UnsafeBufferPointer(start: buffer, count: bytes.count)), bytes)
        var sent = Data(); var writes = 0
        XCTAssertTrue(PacketStreamIO.writePacket(fd: -1, packet: Data(bytes), family: UInt32(AF_INET)) { _, vectors, count in
            writes += 1
            if writes == 2 || writes == 5 { errno = EINTR; return -1 }
            var allowance = 3; var written = 0
            for index in 0..<Int(count) {
                let size = min(allowance, vectors[index].iov_len)
                if size > 0 { sent.append(Data(bytes: vectors[index].iov_base!, count: size)) }
                allowance -= size; written += size
                if allowance == 0 { break }
            }
            return written
        })
        XCTAssertEqual(sent, Data([0, 0, 0, UInt8(AF_INET)] + bytes))
        XCTAssertFalse(PacketStreamIO.readExactly(fd: -1, buffer: buffer, count: 4) { _, _, _ in 0 })
        XCTAssertFalse(PacketStreamIO.writePacket(fd: -1, packet: Data(bytes), family: UInt32(AF_INET)) { _, _, _ in errno = EPIPE; return -1 })
    }

    func testPacketDNSProbeRejectsWrongTupleAndFailedDNSReplies() throws {
        let probe = try XCTUnwrap(TunnelDNSProbe(server: "1.1.1.1"))
        var reply = Array(probe.packet)
        reply.replaceSubrange(12..<16, with: probe.packet[16..<20])
        reply.replaceSubrange(16..<20, with: probe.packet[12..<16])
        reply.replaceSubrange(20..<22, with: probe.packet[22..<24])
        reply.replaceSubrange(22..<24, with: probe.packet[20..<22])
        reply[30] = 0x81; reply[31] = 0x80; reply[35] = 1
        XCTAssertTrue(probe.matches(Data(reply), family: UInt32(AF_INET)))
        XCTAssertTrue(probe.succeeded(Data(reply)))
        reply[31] = 0x82
        XCTAssertFalse(probe.succeeded(Data(reply)))
        reply[31] = 0x80; reply[29] ^= 1
        XCTAssertFalse(probe.matches(Data(reply), family: UInt32(AF_INET)))
        XCTAssertFalse(probe.succeeded(Data(reply)))
    }

    @MainActor func testRealTUNPacketDNSRoundTripDetectsPacketDeliveryFailureAndRestarts() async throws {
        let queue = DispatchQueue(label: "tndtun.test-packet-dns")
        let listener = try NWListener(using: .udp, on: .any)
        let ready = expectation(description: "Local DNS fixture ready")
        listener.stateUpdateHandler = { if case .ready = $0 { ready.fulfill() } }
        listener.newConnectionHandler = { connection in
            connection.start(queue: queue)
            connection.receiveMessage { data, _, _, _ in
                guard let data, data.count >= 12 else { connection.cancel(); return }
                var reply = data
                reply[2] = 0x81; reply[3] = 0x80; reply[6] = 0; reply[7] = 1
                reply.append(contentsOf: [0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 7])
                connection.send(content: reply, completion: .contentProcessed { _ in connection.cancel() })
            }
        }
        listener.start(queue: queue)
        defer { listener.cancel() }
        await fulfillment(of: [ready], timeout: 5)
        let port = try XCTUnwrap(listener.port).rawValue
        let root: [String: Any] = [
            "log": ["loglevel": "warning"],
            "dns": ["servers": [["address": "127.0.0.1", "port": port]], "queryStrategy": "UseIPv4"],
            "outbounds": [["tag": "proxy", "protocol": "freedom", "settings": [:]], ["tag": "kindly-dns", "protocol": "dns", "settings": [:]]],
            "routing": ["rules": [["type": "field", "inboundTag": ["in_proxy"], "port": "53", "outboundTag": "kindly-dns"]]]
        ]
        let json = String(decoding: try JSONSerialization.data(withJSONObject: root), as: UTF8.self)
        let path = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".json")
        defer { try? FileManager.default.removeItem(at: path) }
        let flow = TestSystemPacketFlow()
        let bridge = XrayBridge(packetFlow: flow)
        defer { bridge.stop() }
        for cycle in 0..<2 {
            if cycle == 1 { bridge.stop(); flow.rejectWrites = false }
            try bridge.start(config: .json(json), dataDir: Bundle.main.resourceURL!, finalConfigPath: path)
            let probe = try XCTUnwrap(TunnelDNSProbe(server: "1.1.1.1"))
            let response = await bridge.exchangePacket(probe.packet, family: UInt32(AF_INET), timeout: 5, matching: { probe.matches($0, family: $1) })
            XCTAssertTrue(probe.succeeded(try XCTUnwrap(response)), "DNS must traverse the real TUN socket, not just a local proxy")
            XCTAssertNil(bridge.forwardingFailure)
            if cycle == 0 {
                flow.rejectWrites = true
                flow.deliver(probe.packet)
                for _ in 0..<100 where bridge.forwardingFailure == nil { try await Task.sleep(for: .milliseconds(20)) }
                XCTAssertNotNil(bridge.forwardingFailure, "A broken iOS packet writer must not retain a healthy VPN status")
                let rejected = await bridge.exchangePacket(probe.packet, family: UInt32(AF_INET), timeout: 1, matching: { probe.matches($0, family: $1) })
                XCTAssertNil(rejected)
                flow.rejectWrites = false
                var repairs = 0
                _ = try await AmneziaPacketRepair.run(isCurrent: { true },
                    packetChannelFailed: { bridge.forwardingFailure != nil }, repair: {
                        repairs += 1
                        bridge.stop()
                        try bridge.start(config: .json(json), dataDir: Bundle.main.resourceURL!, finalConfigPath: path)
                    }, verify: {
                    let reply = await bridge.exchangePacket(probe.packet, family: UInt32(AF_INET), timeout: 1,
                                                            matching: { probe.matches($0, family: $1) })
                    return reply.map { probe.succeeded($0) ? 1 : nil } ?? nil
                })
                XCTAssertEqual(repairs, 1)
                XCTAssertNil(bridge.forwardingFailure)
            } else {
                flow.deliver(probe.packet)
                for _ in 0..<100 where flow.deliveredCount == 0 { try await Task.sleep(for: .milliseconds(20)) }
                XCTAssertGreaterThan(flow.deliveredCount, 0, "System packets must resume after a runtime restart")
            }
        }
    }

    @MainActor func testPhysicalAmneziaTransfersRealSystemDNSAndHTTPS() async throws {
        #if targetEnvironment(simulator) || targetEnvironment(macCatalyst)
        throw XCTSkip("Requires an authorized physical iPad connection.")
        #else
        guard ProcessInfo.processInfo.environment["TNDTUN_LIVE_AMNEZIA_FIX"] == "1" else {
            throw XCTSkip("Opt in with TNDTUN_LIVE_AMNEZIA_FIX=1; reconnects the saved Amnezia profile.")
        }
        let store = SimpleStore()
        let value = try XCTUnwrap(store.configurations.first { $0.mode == .amnezia })
        let runtime = AppStore()
        runtime.applyAutomation(autoCaptcha: store.autoCaptcha, autoRecovery: true, turnCheckInterval: store.turnCheckInterval)
        runtime.applySplitTunneling(from: store)
        try runtime.prepare(value)
        let vpn = VPNManager()
        await vpn.load()
        await vpn.connect(using: runtime)
        let deadline = Date().addingTimeInterval(120)
        while !vpn.isConnected && Date() < deadline {
            if let error = vpn.lastError { XCTFail(error); return }
            try await Task.sleep(for: .seconds(1))
        }
        XCTAssertTrue(vpn.isConnected, "Amnezia failed the TCP and packet-DNS startup check")
        let latency = await vpn.refreshLatency()
        XCTAssertNotNil(latency)
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 20; config.timeoutIntervalForResource = 25
        let session = URLSession(configuration: config)
        defer { session.invalidateAndCancel() }
        for raw in ["https://www.gstatic.com/generate_204", "https://www.youtube.com/", "https://speed.cloudflare.com/__down?bytes=1048576"] {
            let (data, response) = try await session.data(from: URL(string: raw)!)
            let status = try XCTUnwrap(response as? HTTPURLResponse).statusCode
            XCTAssertTrue((200..<400).contains(status))
            if raw.contains("bytes=") { XCTAssertGreaterThanOrEqual(data.count, 1_048_576) }
            print("Amnezia iPad system HTTPS: \(URL(string: raw)!.host!), status=\(status), bytes=\(data.count)")
        }
        // Keep the successfully tested VPN running for the background test.
        #endif
    }

    @MainActor func testPhysicalPreparedAmneziaRestartsWithoutRewritingRuntime() async throws {
        #if !DEBUG || targetEnvironment(simulator) || targetEnvironment(macCatalyst)
        throw XCTSkip("Requires the authorized physical iPad and its prepared Amnezia VPN.")
        #else
        guard ProcessInfo.processInfo.environment["TNDTUN_RESTART_PREPARED_AMNEZIA"] == "1" else {
            throw XCTSkip("Opt in explicitly to restart the existing prepared Amnezia VPN.")
        }
        func preparedRuntime() -> String? {
            AppGroup.activeConfigURL.flatMap { try? String(contentsOf: $0, encoding: .utf8) }
                ?? AppGroup.defaults.string(forKey: AppGroup.activeConfigKey)
        }
        let before = try XCTUnwrap(preparedRuntime())
        let previous = AppGroup.defaults.data(forKey: AppGroup.recoveryStatusKey)
            .flatMap { try? JSONDecoder().decode(TunnelRecoverySnapshot.self, from: $0) }
        let vpn = VPNManager()
        try await vpn.restartPreparedAmneziaForDiagnostic()
        let deadline = Date().addingTimeInterval(45)
        while !vpn.isConnected && Date() < deadline { try await Task.sleep(for: .milliseconds(200)) }
        XCTAssertTrue(vpn.isConnected, "Prepared Amnezia did not finish route verification")
        // Compare privately: XCTest must not print the raw runtime/credentials.
        XCTAssertTrue(preparedRuntime() == before, "Diagnostic restart rewrote the prepared runtime")
        let current = try JSONDecoder().decode(TunnelRecoverySnapshot.self,
            from: XCTUnwrap(AppGroup.defaults.data(forKey: AppGroup.recoveryStatusKey)))
        XCTAssertNotNil(current.providerProcessID)
        if let previousPID = previous?.providerProcessID {
            XCTAssertNotEqual(current.providerProcessID, previousPID, "The old extension process was not replaced")
        }
        let latency = await vpn.refreshLatency()
        XCTAssertNotNil(latency, "Prepared Amnezia must pass forced-tunnel HTTPS and packet DNS")
        #endif
    }

    @MainActor func testPhysicalAmneziaResumeKeepsProviderAndTransfersSystemHTTPS() async throws {
        #if targetEnvironment(simulator) || targetEnvironment(macCatalyst)
        throw XCTSkip("Requires an authorized physical iPad connection.")
        #else
        guard ProcessInfo.processInfo.environment["TNDTUN_LIVE_AMNEZIA_FIX"] == "1" else {
            throw XCTSkip("Opt in to a read-only check of the running Amnezia VPN.")
        }
        let vpn = VPNManager()
        await vpn.load()
        let beforeData = try XCTUnwrap(AppGroup.defaults.data(forKey: AppGroup.recoveryStatusKey))
        let before = try JSONDecoder().decode(TunnelRecoverySnapshot.self, from: beforeData)
        let expected = Int(ProcessInfo.processInfo.environment["TNDTUN_EXPECT_PROVIDER_PID"] ?? "")
        if let expected { XCTAssertEqual(before.providerProcessID, expected) }
        let deadline = Date().addingTimeInterval(90)
        while !vpn.isConnected && Date() < deadline { try await Task.sleep(for: .seconds(1)) }
        XCTAssertTrue(vpn.isConnected)
        let latency = await vpn.refreshLatency()
        XCTAssertNotNil(latency, "Forced Amnezia HTTPS plus packet-DNS must respond; DIRECT alone is insufficient")
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 20; config.timeoutIntervalForResource = 25
        let session = URLSession(configuration: config)
        defer { session.invalidateAndCancel() }
        for raw in ["https://www.gstatic.com/generate_204", "https://www.youtube.com/", "https://speed.cloudflare.com/__down?bytes=1048576"] {
            let (data, response) = try await session.data(from: URL(string: raw)!)
            let status = try XCTUnwrap(response as? HTTPURLResponse).statusCode
            XCTAssertTrue((200..<400).contains(status))
            if raw.contains("bytes=") { XCTAssertGreaterThanOrEqual(data.count, 1_048_576) }
            print("After idle, iPad system HTTPS: \(URL(string: raw)!.host!), status=\(status), bytes=\(data.count)")
        }
        let after = try JSONDecoder().decode(TunnelRecoverySnapshot.self, from: XCTUnwrap(AppGroup.defaults.data(forKey: AppGroup.recoveryStatusKey)))
        XCTAssertEqual(after.providerProcessID, before.providerProcessID, "Validation must preserve the provider and split routes")
        #endif
    }

    static let native = """
    [Interface]
    PrivateKey = \(Data(repeating: 17, count: 32).base64EncodedString())
    Address = 10.80.0.2/32
    DNS = 10.80.0.1, 1.1.1.1
    Jc = 3
    Jmin = 30
    Jmax = 60
    S1 = 17
    S2 = 19
    S3 = 13
    S4 = 15
    H1 = 150-200
    H2 = 250-300
    H3 = 350-400
    H4 = 450-500
    I1 = <b 0x12345678><r 20>
    HeaderProtectionKey = \(Data(repeating: 34, count: 32).base64EncodedString())
    RandomTrailers = on
    DisableCookies = on
    [Peer]
    PublicKey = \(Data(repeating: 51, count: 32).base64EncodedString())
    PresharedKey = \(Data(repeating: 68, count: 32).base64EncodedString())
    Endpoint = 203.0.113.25:47891
    AllowedIPs = 0.0.0.0/0, ::/0
    PersistentKeepalive = 25
    """

    static func shareKey(native: String = native) throws -> String {
        let config = try JSONSerialization.data(withJSONObject: ["config": native])
        let root: [String: Any] = ["containers": [["container": "amnezia-awg2", "awg": ["last_config": String(decoding: config, as: UTF8.self)]]], "defaultContainer": "amnezia-awg2", "description": "My Amnezia", "format_version": 1]
        let data = try JSONSerialization.data(withJSONObject: root)
        var length = compressBound(uLong(data.count)); var compressed = Data(count: Int(length))
        let result = compressed.withUnsafeMutableBytes { target in data.withUnsafeBytes { source in
            compress2(target.bindMemory(to: Bytef.self).baseAddress, &length, source.bindMemory(to: Bytef.self).baseAddress, uLong(data.count), 8)
        } }
        XCTAssertEqual(result, Z_OK); compressed.count = Int(length)
        var size = UInt32(data.count).bigEndian
        var payload = withUnsafeBytes(of: &size) { Data($0) }; payload.append(compressed)
        return "vpn://" + payload.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
    func testOfficialShareFormatPreservesAWG3SettingsAndSplitRules() throws {
        var value = SimpleConfiguration(); value.mode = .amnezia; value.amneziaKey = try Self.shareKey()
        value = try value.validated(forConnection: true)
        XCTAssertEqual(value.title, "My Amnezia"); XCTAssertEqual(value.detail, "AmneziaWG")
        XCTAssertFalse(value.profile.isTURN)
        let payload = try XCTUnwrap(value.profile.amneziaRuntimeJSON)
        let runtime = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(payload.utf8)) as? [String: Any])
        XCTAssertEqual(runtime["addresses"] as? [String], ["10.80.0.2"])
        let uapi = try XCTUnwrap(runtime["uapi"] as? String)
        XCTAssertTrue(uapi.contains("h1=150-200\n")); XCTAssertTrue(uapi.contains("s4=15\n"))
        XCTAssertTrue(uapi.contains("random_trailers=true\n")); XCTAssertTrue(uapi.contains("disable_cookies=true\n"))
        XCTAssertTrue(uapi.contains("i1=<b 0x12345678><r 20>\n"))
        XCTAssertTrue(uapi.contains("header_protection_key=" + String(repeating: "22", count: 32)))
        for mode in [SplitTunnelMode.bypassSelected, .tunnelSelected] {
            var settings = AppSettings(); settings.routingMode = .global
            var split = SplitTunnelSettings(); split.mode = mode
            split.setEntries([SplitTunnelEntry(address: "example.com", networks: ["203.0.113.0/24"])], for: mode)
            settings.splitTunneling = split
            let json = XrayConfigurationBuilder.build(profile: value.profile, settings: settings)
            let baseline = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
            let effective = TemporaryFullTunnelPolicy.applying(to: settings, isTURN: false, isDNS: false, isAmnezia: true, full: false)
            let root = TunnelConfiguration.applying(to: baseline, settings: effective, isTURN: false)
            XCTAssertNotNil(root["tndtun_amnezia"])
            let rules = try XCTUnwrap((root["routing"] as? [String: Any])?["rules"] as? [[String: Any]])
            XCTAssertFalse(rules.contains { ($0["domain"] as? [String])?.contains("domain:example.com") == true })
            let selected = rules.first { ($0["ip"] as? [String])?.contains("203.0.113.0/24") == true }
            XCTAssertEqual(selected?["outboundTag"] as? String, mode == .bypassSelected ? "direct" : "proxy")
            let fallback = rules.first { $0["network"] as? String == "tcp,udp" }
            XCTAssertEqual(fallback?["outboundTag"] as? String, mode == .bypassSelected ? "proxy" : "direct")
            settings.amneziaSplitPreference = false
            let disabled = TemporaryFullTunnelPolicy.applying(to: settings, isTURN: false, isDNS: false, isAmnezia: true, full: false)
            let unsplitRoot = TunnelConfiguration.applying(to: baseline, settings: disabled, isTURN: false)
            let unsplitRules = try XCTUnwrap((unsplitRoot["routing"] as? [String: Any])?["rules"] as? [[String: Any]])
            XCTAssertFalse(unsplitRules.contains { ($0["ip"] as? [String])?.contains("203.0.113.0/24") == true })
            let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".json")
            defer { try? FileManager.default.removeItem(at: file) }
            try JSONSerialization.data(withJSONObject: root).write(to: file)
            try SwiftyXray.testConfiguration(dataDir: Bundle.main.resourceURL!.path, configPath: file.path)
        }
    }
    @MainActor func testAmneziaBackupAndModePersistenceRetainAllCredentials() throws {
        let suite = "amnezia-tests-" + UUID().uuidString
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite)); defer { defaults.removePersistentDomain(forName: suite) }
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(suite)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = SimpleStore(fileURL: directory.appendingPathComponent("profiles.json"), defaults: defaults)
        var value = SimpleConfiguration(); value.mode = .amnezia; value.amneziaKey = try Self.shareKey()
        try store.save(value); store.mode = .amnezia
        let restored = SimpleStore(fileURL: directory.appendingPathComponent("profiles.json"), defaults: defaults)
        XCTAssertEqual(restored.visibleConfigurations.count, 1)
        XCTAssertEqual(restored.configurations.first?.amneziaKey, value.amneziaKey)
        let backup = try store.backup()
        let decoded = try ApplicationBackup.decode(backup.encoded())
        XCTAssertEqual(decoded.amneziaCount, 1)
        XCTAssertEqual(decoded.profiles.first?.amneziaKey, value.amneziaKey)
    }
    func testAuthorizedAmneziaRuntimeStartsInSimulator() throws {
        #if targetEnvironment(simulator)
        let input = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent("amnezia-test-runtime.json")
        guard FileManager.default.fileExists(atPath: input.path) else { throw XCTSkip("Requires an authorized local simulator fixture") }
        let payload = try JSONSerialization.jsonObject(with: Data(contentsOf: input))
        let port = try XCTUnwrap(SwiftyXray.getFreePorts(1).first)
        let root: [String: Any] = ["tndtun_amnezia": payload, "inbounds": [["protocol": "socks", "listen": "127.0.0.1", "port": port, "settings": ["udp": true]]],
            "outbounds": [["tag": "proxy", "protocol": "socks", "settings": ["servers": [["address": "127.0.0.1", "port": 9004]]]]]]
        let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".json")
        defer { try? FileManager.default.removeItem(at: file) }
        try JSONSerialization.data(withJSONObject: root).write(to: file)
        for _ in 0..<2 {
            try SwiftyXray.run(dataDir: Bundle.main.resourceURL!.path, configPath: file.path)
            try SwiftyXray.stop()
        }
        #else
        throw XCTSkip("Simulator-only fixture; never changes the host VPN")
        #endif
    }

    @MainActor func testAuthorizedAmneziaProfileTransfersHTTPSInSimulator() async throws {
        #if targetEnvironment(simulator)
        let input = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent("amnezia-test-runtime.json")
        guard FileManager.default.fileExists(atPath: input.path) else { throw XCTSkip("Requires an authorized local simulator fixture") }
        var profile = VPNProfile(); profile.kind = .socks; profile.address = "127.0.0.1"; profile.port = 9004; profile.security = .none
        profile.amneziaRuntimeJSON = try String(contentsOf: input, encoding: .utf8)
        var settings = AppSettings(); settings.routingMode = .global
        settings.connectivityTestURL = "https://www.google.com/generate_204"
        let latency = await ProfilePinger.ping(profile, settings: settings)
        XCTAssertNotNil(latency, "The isolated simulator proxy must transfer HTTPS through the authorized Amnezia key")
        if let latency { print("Amnezia simulator HTTPS latency: \(latency) ms") }
        #else
        throw XCTSkip("Simulator-only fixture; never changes the host VPN")
        #endif
    }

    func testAmneziaStartupErrorHasReadableDescription() throws {
        let connection = try AmneziaImporter.parse(Self.native.replacingOccurrences(of: "H1 = 150-200", with: "H1 = invalid"))
        let json = XrayConfigurationBuilder.build(profile: connection.profile, settings: AppSettings())
        let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".json")
        defer { try? SwiftyXray.stop(); try? FileManager.default.removeItem(at: file) }
        try Data(json.utf8).write(to: file)
        XCTAssertThrowsError(try SwiftyXray.run(dataDir: Bundle.main.resourceURL!.path, configPath: file.path)) { error in
            XCTAssertTrue(error.localizedDescription.contains("invalid Amnezia protocol parameters"))
            XCTAssertFalse(error.localizedDescription.contains("eyJ"))
        }
    }

    func testInvalidKeysAndOversizedCompressedPayloadAreRejected() throws {
        for key in ["vpn://broken", "vpn://_____3jaAA", "", Self.native.replacingOccurrences(of: "[Peer]", with: "PostUp = bad\n[Peer]"), Self.native.replacingOccurrences(of: "H1 = 150-200", with: "UnknownSetting = 1")] {
            XCTAssertThrowsError(try AmneziaImporter.parse(key))
        }
        XCTAssertThrowsError(try AmneziaImporter.parse(try Self.shareKey(native: Self.native.replacingOccurrences(of: "PrivateKey =", with: "WrongKey ="))))
    }
    func testOlderProfilesDecodeWithoutAmneziaFields() throws {
        let old = SimpleConfiguration()
        let bytes = try JSONEncoder().encode(old)
        let decoded = try JSONDecoder().decode(SimpleConfiguration.self, from: bytes)
        XCTAssertEqual(decoded.mode, .turn); XCTAssertNil(decoded.amneziaKey)
    }
    func testXrayImportKeepsAppRoutingAndDNS() throws {
        let outbound: [String: Any] = ["protocol": "vless", "settings": ["vnext": [["address": "vpn.example.com", "port": 443, "users": [["id": "9f774dc1-395b-4397-890a-123456789abc", "encryption": "none"]]]]], "streamSettings": ["network": "tcp", "security": "tls", "tlsSettings": ["serverName": "vpn.example.com"]]]
        let data = try JSONSerialization.data(withJSONObject: ["outbounds": [outbound], "routing": ["rules": [["outboundTag": "wrong"]]], "dns": ["servers": ["wrong.invalid"]]])
        let imported = try AmneziaImporter.parse(String(decoding: data, as: UTF8.self))
        let built = XrayConfigurationBuilder.build(profile: imported.profile, settings: AppSettings())
        XCTAssertFalse(built.contains("wrong")); XCTAssertTrue(built.contains("vpn.example.com"))
    }
}

private final class TestSystemPacketFlow: XrayPacketFlow, @unchecked Sendable {
    private let lock = NSLock()
    private var callback: (@Sendable ([Data], [NSNumber]) -> Void)?
    private var rejected = false
    private var count = 0
    var rejectWrites: Bool {
        get { lock.lock(); defer { lock.unlock() }; return rejected }
        set { lock.lock(); rejected = newValue; lock.unlock() }
    }
    var deliveredCount: Int { lock.lock(); defer { lock.unlock() }; return count }
    func readPackets(completionHandler: @escaping @Sendable ([Data], [NSNumber]) -> Void) {
        lock.lock(); callback = completionHandler; lock.unlock()
    }
    func deliver(_ packet: Data) {
        lock.lock(); let read = callback; callback = nil; lock.unlock()
        read?([packet], [NSNumber(value: AF_INET)])
    }
    func writePackets(_ packets: [Data], withProtocols protocols: [NSNumber]) -> Bool {
        lock.lock(); defer { lock.unlock() }
        if rejected { return false }
        count += packets.count
        return true
    }
}


/// Exercises the provider-owned recovery driver without starting a native core,
/// changing a system VPN, accessing saved profiles or depending on real time.
final class AmneziaRecoveryCoordinatorTests: XCTestCase {
    @MainActor func testHealthySoftRepairKeepsExistingRoutesAndEngine() async throws {
        let fixture = AmneziaRecoveryFixture()
        fixture.onVerify = { _, transportOnly in
            XCTAssertFalse(transportOnly)
            return 42
        }

        let latency = try await AmneziaRecoveryCoordinator.run(fixture.hooks(), packetChannelFailed: false)

        XCTAssertEqual(latency, 42)
        XCTAssertEqual(fixture.softRepairs, 1)
        XCTAssertEqual(fixture.rebuilds, 0)
        XCTAssertEqual(fixture.releases, 0)
        XCTAssertEqual(fixture.restores, 0)
        XCTAssertFalse(fixture.released)
    }

    @MainActor func testBrokenPacketChannelReleasesRoutesBeforeRebuildAndRestoresOnlyAfterPreflight() async throws {
        let fixture = AmneziaRecoveryFixture()
        fixture.onVerify = { fixture, transportOnly in
            if transportOnly {
                XCTAssertTrue(fixture.released, "Background transport checks must leave ordinary traffic available")
                return 37
            }
            return fixture.restores == 0 ? nil : 38
        }

        let latency = try await AmneziaRecoveryCoordinator.run(fixture.hooks(), packetChannelFailed: true)

        XCTAssertEqual(latency, 38)
        XCTAssertEqual(fixture.softRepairs, 0, "A concrete broken packet channel needs an engine replacement")
        XCTAssertEqual(fixture.rebuilds, 1)
        XCTAssertEqual(fixture.releases, 1)
        XCTAssertEqual(fixture.restores, 1)
        XCTAssertFalse(fixture.released)
        XCTAssertEqual(fixture.operations, ["release", "rebuild", "verify-transport", "restore", "verify-full"])
        XCTAssertEqual(fixture.pauses, 0, "A verified first background retry need not wait for a cooldown")
    }

    @MainActor func testUnresponsiveRepairCannotHoldCapturedRoutesBeyondItsBudget() async throws {
        let fixture = AmneziaRecoveryFixture()
        var releasedAt: TimeInterval?
        fixture.onRelease = { fixture in releasedAt = fixture.clock }
        fixture.onVerify = { fixture, transportOnly in
            if transportOnly || fixture.restores > 0 { return 45 }
            guard let deadline = fixture.verificationDeadlines.last else { XCTFail("Probe deadline was not recorded"); return nil }
            fixture.clock = deadline
            return nil // Model a probe that uses its complete deadline.
        }

        let latency = try await AmneziaRecoveryCoordinator.run(fixture.hooks(), packetChannelFailed: false)

        XCTAssertEqual(latency, 45)
        XCTAssertLessThanOrEqual(try XCTUnwrap(releasedAt), 30,
                                 "A nonresponding endpoint must release captured routes within the recovery budget")
        XCTAssertEqual(fixture.releases, 1)
        XCTAssertEqual(fixture.restores, 1)
    }

    @MainActor func testSlowRebuildRunsWithRoutesAlreadyReleased() async throws {
        let fixture = AmneziaRecoveryFixture()
        fixture.onRebuild = { fixture in
            if fixture.rebuilds == 1 { fixture.clock = 31 }
        }
        fixture.onVerify = { fixture, transportOnly in
            XCTAssertTrue(transportOnly || fixture.restores > 0,
                          "An elapsed captured recovery budget must release routes before any further probe")
            return 32
        }

        let latency = try await AmneziaRecoveryCoordinator.run(fixture.hooks(), packetChannelFailed: true)

        XCTAssertEqual(latency, 32)
        XCTAssertEqual(fixture.releases, 1)
        XCTAssertEqual(fixture.restores, 1)
        XCTAssertEqual(fixture.operations, ["release", "rebuild", "verify-transport", "restore", "verify-full"])
    }

    @MainActor func testHourOfflineDoesNotConsumeAttemptsAndRecoversWithoutAnAppAction() async throws {
        let fixture = AmneziaRecoveryFixture()
        fixture.networkAvailable = false
        fixture.onPause = { fixture, _ in
            XCTAssertTrue(fixture.released, "Offline waiting must not retain dead VPN routes")
            XCTAssertEqual(fixture.rebuilds, 0)
            XCTAssertEqual(fixture.restores, 0)
            if fixture.clock >= 3_600 { fixture.networkAvailable = true }
        }
        fixture.onVerify = { fixture, transportOnly in
            XCTAssertGreaterThanOrEqual(fixture.clock, 3_600)
            if transportOnly { XCTAssertTrue(fixture.released) }
            return 49
        }

        let latency = try await AmneziaRecoveryCoordinator.run(fixture.hooks(), packetChannelFailed: false)

        XCTAssertEqual(latency, 49)
        XCTAssertEqual(fixture.maximumOfflineAttempt, 0)
        XCTAssertEqual(fixture.softRepairs, 0)
        XCTAssertEqual(fixture.rebuilds, 1)
        XCTAssertEqual(fixture.releases, 1)
        XCTAssertEqual(fixture.restores, 1)
        XCTAssertTrue(fixture.stages.contains { $0.0 == .waitingForNetwork })
    }

    @MainActor func testOldPathSuccessCannotRestoreRoutesAndFreshPathRetriesWithoutBackoff() async throws {
        let fixture = AmneziaRecoveryFixture()
        var firstPreflightTime: TimeInterval?
        var secondPreflightTime: TimeInterval?
        fixture.onVerify = { fixture, transportOnly in
            guard transportOnly else { return fixture.restores == 0 ? nil : 61 }
            XCTAssertTrue(fixture.released)
            if firstPreflightTime == nil {
                firstPreflightTime = fixture.clock
                fixture.revision += 1 // Wi-Fi changes while the old-network reply arrives.
                return 19
            }
            secondPreflightTime = fixture.clock
            XCTAssertEqual(fixture.restores, 0, "The old path's successful reply must be discarded")
            return 53
        }

        let latency = try await AmneziaRecoveryCoordinator.run(fixture.hooks(), packetChannelFailed: true)

        XCTAssertEqual(latency, 61)
        XCTAssertEqual(fixture.restores, 1)
        XCTAssertEqual(fixture.rebuilds, 2)
        let first = try XCTUnwrap(firstPreflightTime)
        let second = try XCTUnwrap(secondPreflightTime)
        XCTAssertLessThan(second - first, 15, "A new physical path must not inherit the failed path's cooldown")
    }

    @MainActor func testUnavailableServerRetriesWithCappedBackoffWhileRoutesStayReleased() async throws {
        let fixture = AmneziaRecoveryFixture()
        var rebuildTimes: [TimeInterval] = []
        fixture.onRebuild = { fixture in
            rebuildTimes.append(fixture.clock)
            if fixture.rebuilds == 8 { fixture.current = false }
        }
        fixture.onVerify = { _, _ in nil }
        fixture.onPause = { fixture, _ in
            XCTAssertTrue(fixture.released, "Retry delays must preserve ordinary internet access")
        }

        do {
            _ = try await AmneziaRecoveryCoordinator.run(fixture.hooks(), packetChannelFailed: true)
            XCTFail("The user's stop must terminate an otherwise persistent retry sequence")
        } catch { XCTAssertTrue(error is CancellationError) }

        XCTAssertEqual(rebuildTimes, [0, 15, 45, 105, 225, 525, 825, 1125])
        XCTAssertEqual(fixture.restores, 0)
        XCTAssertTrue(fixture.released)
    }

    @MainActor func testLateRebuildCannotReviveStoppedOrReplacedConnection() async throws {
        let fixture = AmneziaRecoveryFixture()
        fixture.onRebuild = { fixture in fixture.current = false }

        do {
            _ = try await AmneziaRecoveryCoordinator.run(fixture.hooks(), packetChannelFailed: true)
            XCTFail("A rebuild completing after Disconnect must not resume recovery")
        } catch { XCTAssertTrue(error is CancellationError) }

        XCTAssertEqual(fixture.rebuilds, 1)
        XCTAssertEqual(fixture.verifications, 0)
        XCTAssertEqual(fixture.restores, 0)
    }

    @MainActor func testLatePreflightCannotRestoreAfterRevocation() async throws {
        let fixture = AmneziaRecoveryFixture()
        fixture.onVerify = { fixture, transportOnly in
            if transportOnly {
                fixture.current = false // The same session gate covers profile replacement and access revocation.
                return 27
            }
            return nil
        }

        do {
            _ = try await AmneziaRecoveryCoordinator.run(fixture.hooks(), packetChannelFailed: true)
            XCTFail("A revoked connection must not accept a late successful transport probe")
        } catch { XCTAssertTrue(error is CancellationError) }

        XCTAssertEqual(fixture.releases, 1)
        XCTAssertEqual(fixture.restores, 0)
        XCTAssertTrue(fixture.released)
    }

    @MainActor func testNetworkSettingsClearFailureDoesNotEnterUnsafeStandbyOrRetry() async throws {
        let fixture = AmneziaRecoveryFixture()
        fixture.networkAvailable = false
        fixture.onRelease = { _ in throw AmneziaRecoveryFixture.Failure.clearSettings }

        do {
            _ = try await AmneziaRecoveryCoordinator.run(fixture.hooks(), packetChannelFailed: false)
            XCTFail("The provider must see a failed clear and terminate the tunnel safely")
        } catch { XCTAssertEqual(error as? AmneziaRecoveryFixture.Failure, .clearSettings) }

        XCTAssertEqual(fixture.releases, 1)
        XCTAssertFalse(fixture.released)
        XCTAssertEqual(fixture.rebuilds, 0)
        XCTAssertEqual(fixture.restores, 0)
        XCTAssertEqual(fixture.pauses, 0)
        XCTAssertFalse(fixture.stages.contains { stage, _ in
            if case .standby = stage { return true }
            return false
        })
    }

    @MainActor func testFailedPostRestoreVerificationReleasesAgainBeforeCooldown() async throws {
        let fixture = AmneziaRecoveryFixture()
        fixture.onVerify = { fixture, transportOnly in
            if transportOnly { return 21 }
            return fixture.restores >= 2 ? 35 : nil
        }
        fixture.onPause = { fixture, _ in
            XCTAssertTrue(fixture.released, "No retry cooldown may keep an unverified system route installed")
        }

        let latency = try await AmneziaRecoveryCoordinator.run(fixture.hooks(), packetChannelFailed: true)

        XCTAssertEqual(latency, 35)
        XCTAssertEqual(fixture.releases, 2)
        XCTAssertEqual(fixture.restores, 2)
        XCTAssertEqual(fixture.operations, ["release", "rebuild", "verify-transport", "restore", "verify-full", "release", "rebuild", "verify-transport", "restore", "verify-full"])
    }
}

@MainActor private final class AmneziaRecoveryFixture {
    enum Failure: Error, Equatable { case clearSettings, runawayLoop }
    var current = true
    var networkAvailable = true
    var revision: UInt64 = 1
    var clock: TimeInterval = 0
    var released = false
    var softRepairs = 0
    var rebuilds = 0
    var releases = 0
    var restores = 0
    var verifications = 0
    var verificationDeadlines: [TimeInterval] = []
    var pauses = 0
    var maximumOfflineAttempt = 0
    var operations: [String] = []
    var stages: [(AmneziaRecoveryCoordinator.Stage, Int)] = []
    var onPause: ((AmneziaRecoveryFixture, TimeInterval) throws -> Void)?
    var onRebuild: ((AmneziaRecoveryFixture) async throws -> Void)?
    var onRelease: ((AmneziaRecoveryFixture) async throws -> Void)?
    var onVerify: ((AmneziaRecoveryFixture, Bool) async -> Int?)?

    func hooks() -> AmneziaRecoveryCoordinator.Hooks {
        AmneziaRecoveryCoordinator.Hooks(
            isCurrent: { self.current },
            networkAvailable: { self.networkAvailable },
            pathRevision: { self.revision },
            now: { self.clock },
            pause: { seconds in
                self.pauses += 1
                guard self.pauses < 10_000 else { throw Failure.runawayLoop }
                XCTAssertGreaterThan(seconds, 0)
                self.clock += seconds
                try self.onPause?(self, seconds)
            },
            softRepair: { self.softRepairs += 1 },
            rebuild: {
                XCTAssertTrue(self.released, "Slow preparation and engine replacement must never hold system routes")
                self.operations.append("rebuild")
                self.rebuilds += 1
                try await self.onRebuild?(self)
            },
            release: {
                self.operations.append("release")
                self.releases += 1
                try await self.onRelease?(self)
                self.released = true
            },
            restore: {
                self.operations.append("restore")
                self.restores += 1
                XCTAssertTrue(self.released, "Restore is meaningful only after successful route release")
                self.released = false
            },
            verify: { deadline, transportOnly in
                XCTAssertTrue(deadline.isFinite)
                XCTAssertGreaterThan(deadline, self.clock, "Every probe must have a finite remaining attempt budget")
                self.verificationDeadlines.append(deadline)
                self.operations.append(transportOnly ? "verify-transport" : "verify-full")
                self.verifications += 1
                return await self.onVerify?(self, transportOnly)
            },
            update: { stage, attempt in
                self.stages.append((stage, attempt))
                if !self.networkAvailable { self.maximumOfflineAttempt = max(self.maximumOfflineAttempt, attempt) }
            })
    }
}


final class RouteProbeSequenceTests: XCTestCase {
    @MainActor func testPrimaryTimeoutLeavesFallbackAndPacketDNSWithinSharedDeadline() async throws {
        var clock: TimeInterval = 0
        var budgets: [TimeInterval] = []
        let latency = await RouteProbeSequence.measure(deadline: 15, reservedAfter: 6,
            now: { clock }, isCurrent: { true }, primary: { timeout in
                budgets.append(timeout); clock += timeout
                return nil // An endpoint outage uses its entire allocated time.
            }, fallback: { timeout in
                budgets.append(timeout); clock += timeout - 0.1
                return 22
            })
        XCTAssertEqual(latency, 22, "A working independent endpoint must keep this VPN healthy")
        XCTAssertEqual(budgets, [4.5, 4.5])
        XCTAssertGreaterThanOrEqual(15 - clock, 6, "Packet DNS must retain its own verification budget")
    }

    @MainActor func testPathChangeBetweenEndpointsCancelsStaleVerification() async throws {
        var current = true
        let latency = await RouteProbeSequence.measure(deadline: 15,
            now: { 0 }, isCurrent: { current }, primary: { _ in current = false; return nil },
            fallback: { _ in XCTFail("An old path cannot probe or accept its fallback"); return 12 })
        XCTAssertNil(latency)
    }
}


final class AmneziaHealthPolicyTests: XCTestCase {
    func testShortOfflineGapKeepsSessionButPersistentLossReleasesAfterGrace() {
        var health = AmneziaHealthPolicy()
        XCTAssertFalse(health.observeNetwork(available: true, revision: 1, now: 0))
        XCTAssertFalse(health.observeNetwork(available: false, revision: 2, now: 1))
        XCTAssertFalse(health.observeNetwork(available: true, revision: 3, now: 3))
        XCTAssertFalse(health.observeNetwork(available: false, revision: 4, now: 10))
        XCTAssertFalse(health.observeNetwork(available: false, revision: 4, now: 12.9))
        XCTAssertTrue(health.observeNetwork(available: false, revision: 4, now: 13))
    }

    func testNewPhysicalPathDoesNotInheritOldPathFailure() {
        var health = AmneziaHealthPolicy()
        _ = health.observeNetwork(available: true, revision: 1, now: 0)
        XCTAssertFalse(health.recordProbe(succeeded: false, revision: 1))
        _ = health.observeNetwork(available: true, revision: 2, now: 1)
        XCTAssertFalse(health.recordProbe(succeeded: false, revision: 1), "Late old-path failure is discarded")
        XCTAssertFalse(health.recordProbe(succeeded: false, revision: 2), "One new-path failure cannot replace the engine")
        XCTAssertTrue(health.recordProbe(succeeded: false, revision: 2))
    }
}
