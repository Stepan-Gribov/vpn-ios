import XCTest
import CryptoKit
import SwiftyXrayKit
import NetworkExtension
@testable import TnDtun

private final class PanelFixture: @unchecked Sendable {
    let signing = Curve25519.Signing.PrivateKey()
    let device = "12345678-1234-1234-1234-123456789012"
    let clientID = "22345678-1234-1234-1234-123456789012"
    var subscriptionCode: String?
    var subscriptionSync: PanelSubscriptionSync?
    var trust: PanelTrust { PanelTrust(api: "https://panel.example.test/v1", keyID: "0123456789abcdef", publicKey: PanelContract.base64URL(signing.publicKey.rawRepresentation), dns: Self.dns) }
    static let dns = PanelDNS(domain: "dns.example.test", publicKey: String(repeating: "ab", count: 32), resolver: "1.1.1.1:5353", savedResolvers: ["8.8.8.8:53"])
    static var settings: PanelSettings {
        PanelSettings(autoCaptcha: false, autoRecovery: false, turnCheckInterval: 47, dnsServers: ["1.1.1.1:5353"], dnsTunnel: dns,
            splitTunneling: SplitTunnelSettings(mode: .tunnelSelected,
                bypassEntries: [SplitTunnelEntry(address: "direct.test", networks: ["198.51.100.0/24"])],
                tunnelEntries: [SplitTunnelEntry(address: "selected.test", networks: ["203.0.113.0/24"]), SplitTunnelEntry(address: "manual.test")]))
    }
    func payload(nonce: String = "nonce", revision: Int64 = 3) throws -> [String: Any] {
        let xray = """
        {"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"203.0.113.8","port":443,"users":[{"id":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"none"}}]}
        """
        let profiles: [[String: Any]] = (0..<4).map { i in
            var row: [String: Any] = ["id": String(format: "32345678-1234-1234-1234-%012d", i), "mode": i < 2 ? "turn" : "amnezia", "generation": 1,
                "title": "Server \(i)", "location": "Test location \(i)", "inbound_id": "inbound-\(i)", "node_id": "node-\(i)", "credential_scope": "device"]
            if i < 2 {
                row.merge(["server": "203.0.113.9:56010", "callLink": "https://vk.ru/call/join/test", "vlessID": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "wrapKey": ""]) { _, new in new }
            } else { row["amneziaKey"] = xray }
            return row
        }
        var result: [String: Any] = ["format": "TnDtun-package", "schema_version": 1, "revision": revision, "nonce": nonce, "issued_at": "2026-10-15T19:00:00+03:00",
                "client_id": clientID, "client_name": "Test client", "device_id": device, "status": "active", "expires_at": NSNull(), "sync_after_seconds": 10,
                "profiles": profiles, "settings": try JSONSerialization.jsonObject(with: JSONEncoder().encode(Self.settings))]
        if let subscriptionCode { result["subscription_code"] = subscriptionCode }
        if let subscriptionSync {
            var settings = result["settings"] as! [String: Any]
            settings["subscriptionSync"] = ["enabled": subscriptionSync.enabled, "intervalMinutes": subscriptionSync.intervalMinutes]
            result["settings"] = settings
        }
        return result
    }
    func envelope(_ payload: [String: Any]) throws -> Data {
        // Pretty-printing and explicit null must remain the exact signed bytes.
        let raw = try JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys])
        return try envelope(raw: raw)
    }
    func envelope(raw: Data) throws -> Data {
        try JSONSerialization.data(withJSONObject: ["algorithm": "Ed25519", "key_id": trust.keyID, "payload": PanelContract.base64URL(raw), "signature": PanelContract.base64URL(signing.signature(for: raw))])
    }
    func package() throws -> PanelPackage { try PanelContract.verify(envelope(payload()), trust: trust, nonce: "nonce", deviceID: device) }
}

private actor PanelStub: PanelExchanging {
    let fixture: PanelFixture
    var requests: [(String, Data, String?)] = []
    var failures: [Int]
    var block = false
    init(_ fixture: PanelFixture, failures: [Int] = []) { self.fixture = fixture; self.failures = failures }
    func post(trust: PanelTrust, dns: PanelDNS, path: String, body: Data, token: String?, deadline: Date) async throws -> Data {
        requests.append((path, body, token))
        if !failures.isEmpty { throw PanelHTTPFailure(status: failures.removeFirst(), code: "provisioning_pending") }
        if block { try await Task.sleep(for: .seconds(30)) }
        let root = try PanelJSON.parse(body, limit: 16384)
        let nonce = try root.field("nonce").text()
        let envelope = try fixture.envelope(fixture.payload(nonce: nonce))
        if path == "sync" { return envelope }
        return try JSONSerialization.data(withJSONObject: ["device_id": fixture.device, "token": "test-private-token", "package": JSONSerialization.jsonObject(with: envelope)])
    }
    func setBlock() { block = true }
    func failNextRequest(_ status: Int) { failures.append(status) }
}

private actor PanelRouteLog {
    var routes: [PanelTransferRoute] = []
    var requests: [Bool] = []
    var origins: [String] = []
    func route(_ value: PanelTransferRoute) { routes.append(value) }
    func request(_ api: String, _ viaDNS: Bool) {
        origins.append(api)
        requests.append(viaDNS)
    }
}

final class PanelTests: XCTestCase {
    func testSubscriptionSyncPolicyIsOptionalAndStrictlyValidatedAfterSignature() throws {
        let fixture = PanelFixture()
        XCTAssertNil(try fixture.package().settings?.subscriptionSync)
        for minutes in [15, 1440] {
            fixture.subscriptionSync = PanelSubscriptionSync(enabled: true, intervalMinutes: minutes)
            XCTAssertEqual(try fixture.package().settings?.subscriptionSync, fixture.subscriptionSync)
        }
        let invalidPolicies: [[String: Any]] = [
            ["enabled": true, "intervalMinutes": 14],
            ["enabled": false, "intervalMinutes": 1441],
            ["enabled": 1, "intervalMinutes": 30],
            ["enabled": true, "intervalMinutes": "30"],
            ["enabled": true],
        ]
        for policy in invalidPolicies {
            var payload = try fixture.payload()
            var settings = try XCTUnwrap(payload["settings"] as? [String: Any])
            settings["subscriptionSync"] = policy
            payload["settings"] = settings
            XCTAssertThrowsError(try PanelContract.verify(fixture.envelope(payload), trust: fixture.trust,
                                                          nonce: "nonce", deviceID: fixture.device))
        }
    }

    @MainActor func testDueSubscriptionSyncRetriesAndCoalescesWithManualRefresh() async throws {
        let fixture = PanelFixture(), v = vault()
        fixture.subscriptionSync = PanelSubscriptionSync(enabled: true, intervalMinutes: 15)
        let packet = try fixture.package()
        let now = Int64(Date().timeIntervalSince1970)
        let otherID = "12345678-1234-1234-1234-123456789099"
        var otherPayload = try fixture.payload()
        otherPayload["device_id"] = otherID
        otherPayload["profiles"] = []
        let otherPacket = try PanelContract.verify(fixture.envelope(otherPayload),
            trust: fixture.trust, nonce: "nonce", deviceID: otherID)
        try v.transaction { state in
            try state.accept(packet, trust: fixture.trust, token: "test-first", expectedEpoch: 0,
                activation: true, manualIDs: [], baseline: PanelFixture.settings, now: now - 901)
            try state.accept(otherPacket, trust: fixture.trust, token: "test-second", expectedEpoch: 0,
                activation: true, manualIDs: [], baseline: PanelFixture.settings, now: now)
        }
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let store = SimpleStore(fileURL: dir.appendingPathComponent("profiles.json"),
                                defaults: UserDefaults(suiteName: UUID().uuidString)!, panelVault: v)
        let stub = PanelStub(fixture, failures: [500])
        let client = PanelClient(vault: v, exchange: stub, pause: { _ in })
        let panel = PanelManager(store: store, client: client)

        let firstResult = await panel.refreshDueSubscriptions()
        XCTAssertFalse(firstResult)
        let failed = try XCTUnwrap(v.snapshot().subscriptions.first { $0.package.deviceID == fixture.device })
        XCTAssertEqual(failed.lastSync, now - 901)
        XCTAssertGreaterThanOrEqual(try XCTUnwrap(failed.nextSyncAt), now + 900)
        XCTAssertFalse(panel.showingSubscription)
        let earlyResult = await panel.refreshDueSubscriptions()
        XCTAssertTrue(earlyResult)
        let afterRetryCheck = await stub.requests.map { $0.2 }
        XCTAssertEqual(afterRetryCheck, ["test-first"])

        panel.refresh(failed)
        panel.refresh(failed)
        let catchUp = await panel.refreshDueSubscriptions()
        XCTAssertTrue(catchUp)
        let deadline = Date().addingTimeInterval(5)
        while panel.busy && Date() < deadline { try await Task.sleep(for: .milliseconds(10)) }
        XCTAssertFalse(panel.busy)
        let requests = await stub.requests.map { $0.2 }
        XCTAssertEqual(requests, ["test-first", "test-first"])
        let saved = try XCTUnwrap(v.snapshot().subscriptions.first { $0.id == failed.id })
        XCTAssertGreaterThan(saved.lastSync, failed.lastSync)
        XCTAssertEqual(saved.nextSyncAt, saved.lastSync + 900)
        XCTAssertEqual(try v.snapshot().subscriptions.first { $0.package.deviceID == otherID }?.lastSync, now)

        try v.transaction { state in
            let index = try XCTUnwrap(state.subscriptions.firstIndex { $0.id == saved.id })
            state.subscriptions[index].nextSyncAt = now - 1
        }
        panel.setForegroundActive(true)
        defer { panel.setForegroundActive(false) }
        let foregroundDeadline = Date().addingTimeInterval(5)
        while Date() < foregroundDeadline {
            let count = await stub.requests.count
            if count == 3 && !panel.busy { break }
            try await Task.sleep(for: .milliseconds(10))
        }
        let foregroundRequests = await stub.requests.map { $0.2 }
        XCTAssertEqual(foregroundRequests, ["test-first", "test-first", "test-first"])
        XCTAssertEqual(try v.snapshot().subscriptions.first { $0.package.deviceID == otherID }?.lastSync, now)
    }
    func testPanelRouteTriesTrustedDirectAddressesThenDNSOnPrimaryAndStartsDirectAgain() async throws {
        let log = PanelRouteLog()
        let unavailable = try PanelJSON.parse(Data(#"{"error":"direct_unavailable"}"#.utf8), limit: 1024)
        let success = try PanelJSON.parse(Data(#"{"status":200,"transport":"direct","body":"e30="}"#.utf8), limit: 1024)
        _ = try await PanelTransportSequence.run(apis: ["primary", "ip", "legacy"], forceDNS: false, progress: { await log.route($0) }) { api, viaDNS in
            await log.request(api, viaDNS)
            return viaDNS ? success : unavailable
        }
        _ = try await PanelTransportSequence.run(apis: ["primary", "ip", "legacy"], forceDNS: false, progress: { await log.route($0) }) { api, viaDNS in
            await log.request(api, viaDNS); return success
        }
        let routes = await log.routes, requests = await log.requests
        XCTAssertEqual(routes, [.direct, .dns, .direct])
        XCTAssertEqual(requests, [false, false, false, true, false])
        let origins = await log.origins
        XCTAssertEqual(origins, ["primary", "ip", "legacy", "primary", "primary"])
    }

    func testPanelRouteTriesNextDirectOnGatewayFailureWithoutStartingDNS() async throws {
        let log = PanelRouteLog()
        let result = try await PanelTransportSequence.run(apis: ["primary", "ip", "legacy"], forceDNS: false, progress: { await log.route($0) }) { api, viaDNS in
            await log.request(api, viaDNS)
            switch api {
            case "primary": return .object(["status": .number("502")])
            case "ip": return .object(["status": .number("504"), "body": .string(Data("Gateway timeout".utf8).base64EncodedString())])
            default: return .object(["status": .number("200")])
            }
        }
        let routes = await log.routes, origins = await log.origins, requests = await log.requests
        XCTAssertEqual(routes, [.direct])
        XCTAssertEqual(origins, ["primary", "ip", "legacy"])
        XCTAssertEqual(requests, [false, false, false])
        XCTAssertEqual(result.api, "legacy")
        XCTAssertEqual(result.reply, .object(["status": .number("200")]))
    }

    func testPanelRouteDoesNotFallbackForHTTPOrValidationErrors() async throws {
        let responses = [200, 401, 403, 429, 503, 307, 308].map { #"{"status":\#($0),"transport":"direct","body":"e30="}"# }
            + [#"{"status":502,"body":"eyJjb2RlIjoicHJvdmlzaW9uaW5nX3BlbmRpbmcifQ=="}"#]
            + ["response_too_large", "invalid_request", "untrusted_manifest", "physical_network_unavailable", "cancelled"].map { #"{"error":"\#($0)"}"# }
        for json in responses {
            let log = PanelRouteLog(), expected = try PanelJSON.parse(Data(json.utf8), limit: 1024)
            let result = try await PanelTransportSequence.run(apis: ["primary", "ip", "legacy"], forceDNS: false, progress: { await log.route($0) }) { api, viaDNS in
                await log.request(api, viaDNS); return expected
            }
            XCTAssertEqual(result.api, "primary")
            XCTAssertEqual(result.reply, expected)
            let routes = await log.routes, requests = await log.requests
            XCTAssertEqual(routes, [.direct]); XCTAssertEqual(requests, [false])
        }
    }

    func testPanelRouteExplicitForceDNSDoesNotSendDirectRequest() async throws {
        let log = PanelRouteLog()
        _ = try await PanelTransportSequence.run(apis: ["primary", "ip", "legacy"], forceDNS: true, progress: { await log.route($0) }) { api, viaDNS in
            await log.request(api, viaDNS)
            return try PanelJSON.parse(Data(#"{"status":200}"#.utf8), limit: 1024)
        }
        let routes = await log.routes, requests = await log.requests
        XCTAssertEqual(routes, [.dns]); XCTAssertEqual(requests, [true])
        let origins = await log.origins
        XCTAssertEqual(origins, ["primary"])
    }

    func testPanelRouteCancellationAtEitherPhaseBoundaryDoesNotStartDNS() async throws {
        for cancelAtDNSProgress in [false, true] {
            let log = PanelRouteLog()
            let task = Task {
                try await PanelTransportSequence.run(apis: ["primary", "ip", "legacy"], forceDNS: false, progress: { route in
                    await log.route(route)
                    if route == .dns && cancelAtDNSProgress { withUnsafeCurrentTask { $0?.cancel() } }
                }) { api, viaDNS in
                    await log.request(api, viaDNS)
                    if !cancelAtDNSProgress { withUnsafeCurrentTask { $0?.cancel() } }
                    return try PanelJSON.parse(Data(#"{"error":"direct_unavailable"}"#.utf8), limit: 1024)
                }
            }
            do { _ = try await task.value; XCTFail("Expected cancellation") }
            catch is CancellationError {}
            let routes = await log.routes, requests = await log.requests
            XCTAssertEqual(routes, cancelAtDNSProgress ? [.direct, .dns] : [.direct])
            XCTAssertEqual(requests, cancelAtDNSProgress ? [false, false, false] : [false])
        }
    }

    func testSignedPushOverlayIsOptionalAndStrictlyBoolean() throws {
        let fixture = PanelFixture()
        XCTAssertNil(try fixture.package().settings?.splitTunneling.pushNotifications)
        var payload = try fixture.payload(), settings = payload["settings"] as! [String: Any]
        var split = settings["splitTunneling"] as! [String: Any]
        split["pushNotifications"] = ["apple": true, "google": false]
        settings["splitTunneling"] = split; payload["settings"] = settings
        let package = try PanelContract.verify(fixture.envelope(payload), trust: fixture.trust, nonce: "nonce", deviceID: fixture.device)
        XCTAssertEqual(package.settings?.splitTunneling.pushNotifications, PushNotificationSettings(apple: true))
        split["pushNotifications"] = ["apple": 1, "google": false]
        settings["splitTunneling"] = split; payload["settings"] = settings
        XCTAssertThrowsError(try PanelContract.verify(fixture.envelope(payload), trust: fixture.trust, nonce: "nonce", deviceID: fixture.device))
    }
    private func vault() -> PanelVault { PanelVault(directory: FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString), key: Data(repeating: 7, count: 32)) }
    func testLegacySubscriptionCodeBackfillDoesNotApplyPackageOrSettings() async throws {
        let fixture = PanelFixture(), stored = try fixture.package(), v = vault()
        try v.transaction { try $0.accept(stored, trust: fixture.trust, token: "test-private-token", expectedEpoch: 0,
                                         activation: true, manualIDs: [], baseline: PanelFixture.settings, now: 10) }
        let before = try v.snapshot()
        fixture.subscriptionCode = "QWRT"
        let exchange = PanelStub(fixture)
        let client = PanelClient(vault: v, exchange: exchange)
        try await client.recoverSubscriptionCode(XCTUnwrap(before.subscriptions.first))
        var expected = before
        expected.subscriptions[0].subscriptionCode = "QWRT"
        XCTAssertEqual(try v.snapshot(), expected, "Only the display code may change")
        let calls = await exchange.requests
        XCTAssertEqual(calls.count, 1); XCTAssertEqual(calls.first?.0, "sync")
        XCTAssertEqual(calls.first?.2, "test-private-token")
        fixture.subscriptionCode = "ASDF"
        try await client.sync(XCTUnwrap(v.snapshot().subscriptions.first), baseline: PanelFixture.settings, manualIDs: [])
        XCTAssertEqual(try v.snapshot().subscriptions.first?.subscriptionCode, "ASDF", "Explicit refresh reads a rotated current code")
        fixture.subscriptionCode = nil
        XCTAssertNil(try fixture.package().subscriptionCode, "Old signed packages remain compatible")
    }

    func testSubscriptionCodePersistsAcrossReloadAndSyncAndLegacyRecordsDecode() throws {
        let fixture = PanelFixture(), packet = try fixture.package()
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let key = Data(repeating: 19, count: 32)
        let original = PanelVault(directory: directory, key: key)
        try original.transaction { state in
            try state.accept(packet, trust: fixture.trust, token: "test-token", expectedEpoch: 0,
                             activation: true, manualIDs: [], baseline: PanelFixture.settings, now: 0)
            state.subscriptions[0].subscriptionCode = "0012"
        }
        let restarted = PanelVault(directory: directory, key: key)
        XCTAssertEqual(try restarted.snapshot().subscriptions.first?.subscriptionCode, "0012")
        try restarted.transaction { state in
            try state.accept(packet, trust: fixture.trust, token: "test-token", expectedEpoch: 0,
                             activation: false, manualIDs: [], baseline: PanelFixture.settings, now: 1)
        }
        let sub = try XCTUnwrap(restarted.snapshot().subscriptions.first)
        XCTAssertEqual(sub.subscriptionCode, "0012")
        var legacy = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(sub)) as? [String: Any])
        legacy.removeValue(forKey: "subscriptionCode")
        XCTAssertNil(try JSONDecoder().decode(PanelSubscription.self, from: JSONSerialization.data(withJSONObject: legacy)).subscriptionCode)
    }

    func testRawSignatureDistinctProfilesAndBothSplitLists() throws {
        let f = PanelFixture(), p = try f.package()
        XCTAssertEqual(p.profiles.count, 4)
        XCTAssertEqual(Set(p.profiles.map(\.id)).count, 4)
        XCTAssertEqual(p.profiles[0].server, p.profiles[1].server)
        XCTAssertEqual(p.settings?.turnCheckInterval, 47)
        XCTAssertEqual(p.settings?.dnsTunnel?.resolver, "1.1.1.1:5353")
        XCTAssertEqual(p.settings?.splitTunneling.bypassEntries.count, 1)
        XCTAssertEqual(p.settings?.splitTunneling.domains, ["domain:manual.test"])
        XCTAssertEqual(p.settings?.splitTunneling.dnsDomains, ["domain:manual.test", "domain:selected.test"])
        var outer = try JSONSerialization.jsonObject(with: f.envelope(f.payload())) as! [String: Any]
        outer["payload"] = PanelContract.base64URL(Data("{}".utf8))
        XCTAssertThrowsError(try PanelContract.verify(JSONSerialization.data(withJSONObject: outer), trust: f.trust, nonce: "nonce", deviceID: f.device))
    }
    func testStrictJSONRejectsDuplicatesUnicodeTypesDepthAndSize() throws {
        for raw in [#"{"a":1,"\u0061":2}"#, #"{"a":01}"#, #"{"a":true}{}"#, #""\uD800""#, String(repeating: "[", count: 33) + "0" + String(repeating: "]", count: 33)] {
            XCTAssertThrowsError(try PanelJSON.parse(Data(raw.utf8), limit: 1000), raw)
        }
        XCTAssertThrowsError(try PanelJSON.parse(Data([0xff]), limit: 1000))
        XCTAssertThrowsError(try PanelJSON.parse(Data(repeating: 32, count: 1001), limit: 1000))
        for raw in ["true", "1.0", "1e0", "9223372036854775808", "\"1\""] { XCTAssertThrowsError(try PanelJSON.parse(Data(raw.utf8), limit: 1000).integer) }
        XCTAssertEqual(try PanelJSON.parse(Data("9223372036854775807".utf8), limit: 1000).integer, Int64.max)
    }
    func testSignedPayloadAndSettingsSizeLimits() throws {
        let f = PanelFixture()
        XCTAssertThrowsError(try PanelContract.verify(Data(repeating: 32, count: PanelContract.envelopeLimit + 1), trust: f.trust, nonce: "nonce", deviceID: f.device))
        let oversizedPayload = try f.envelope(raw: Data(repeating: 32, count: PanelContract.payloadLimit + 1))
        XCTAssertThrowsError(try PanelContract.verify(oversizedPayload, trust: f.trust, nonce: "nonce", deviceID: f.device))
        var p = try f.payload(), settings = p["settings"] as! [String: Any]
        settings["future_field"] = String(repeating: "x", count: 5 * 1024 * 1024)
        p["settings"] = settings
        XCTAssertThrowsError(try PanelContract.verify(f.envelope(p), trust: f.trust, nonce: "nonce", deviceID: f.device))
    }

    func testShortAndLegacyActivationCodesInTextAndLinks() throws {
        let f = PanelFixture()
        let link = "tndtun://activate?api=https%3A%2F%2Fpanel.example.test%2Fv1&key=\(f.trust.publicKey)&kid=\(f.trust.keyID)&code="
        for raw in ["QWRT", "qwrt", " \tq-w r\nt\u{00a0}"] {
            XCTAssertEqual(try PanelContract.activation(raw, bootstrap: f.trust).code, "QWRT")
        }
        for encoded in ["QWRT", "qwrt", "q-w+r%09t", "q%20w-rt"] {
            let parsed = try PanelContract.activation(link + encoded, bootstrap: f.trust)
            XCTAssertEqual(parsed.code, "QWRT")
            XCTAssertTrue(parsed.trust.sameSource(f.trust))
        }
        let legacy = "234567GHIJKLMNOPQRSTUVWXYZ"
        for raw in [legacy, legacy.lowercased(), " \(legacy.prefix(13))-\(legacy.suffix(13))\n"] {
            XCTAssertEqual(try PanelContract.activation(raw, bootstrap: f.trust).code, legacy)
            let encoded = try XCTUnwrap(raw.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed))
            XCTAssertEqual(try PanelContract.activation(link + encoded, bootstrap: f.trust).code, legacy)
        }
        for bad in ["", "QWR", "QWRTA", "QW2T", "1234", "ЙЦУК", "QWРT", "QW_T", String(repeating: "A", count: 25), String(repeating: "A", count: 27), String(repeating: "A", count: 25) + "8"] {
            XCTAssertThrowsError(try PanelContract.activation(bad, bootstrap: f.trust))
            let encoded = try XCTUnwrap(bad.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed))
            XCTAssertThrowsError(try PanelContract.activation(link + encoded, bootstrap: f.trust))
        }
    }

    func testSubscriptionFormAcceptsOnlyCompleteEnglishKeysWithoutTruncation() throws {
        for (raw, expected) in [("", ""), ("qw", "QW"), ("qWrT", "QWRT"), (" \tq-w r\nt\u{00a0}", "QWRT")] {
            XCTAssertEqual(try PanelContract.subscriptionKeyInput(raw), expected)
        }
        XCTAssertEqual(try PanelContract.subscriptionKey("qwrt"), "QWRT")
        for raw in ["", "q", "qwr"] { XCTAssertThrowsError(try PanelContract.subscriptionKey(raw)) }
        for raw in ["QWRTA", "tndtun://activate?code=QWRT", String(repeating: "A", count: 26),
                    "QW2T", "1234", "ЙЦУК", "QWРT", "QWß", "QW_T", "ＡＢＣＤ", String(repeating: " ", count: 129)] {
            XCTAssertThrowsError(try PanelContract.subscriptionKeyInput(raw))
        }
    }

    @MainActor func testSubscriptionAdditionCoalescesAndRefreshPreservesSavedIdentity() async throws {
        let v = vault(), stub = PanelStub(PanelFixture())
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let store = SimpleStore(fileURL: dir.appendingPathComponent("profiles.json"), defaults: UserDefaults(suiteName: UUID().uuidString)!, panelVault: v)
        let panel = PanelManager(store: store, client: PanelClient(vault: v, exchange: stub, pause: { _ in }), activationService: PanelServiceOrigins(primary: stub.fixture.trust))
        panel.updateSubscriptionKey("qwr")
        XCTAssertFalse(panel.canAddSubscription)
        panel.updateSubscriptionKey("qwrt")
        XCTAssertTrue(panel.canAddSubscription)
        for _ in 0..<15 { panel.addSubscription() }
        XCTAssertEqual(panel.addition, .adding); XCTAssertEqual(panel.pendingCount, 1)
        panel.updateSubscriptionKey("AAAA")
        XCTAssertEqual(panel.activationText, "QWRT", "A pending request owns its submitted key")
        let deadline = Date().addingTimeInterval(5)
        while panel.busy && Date() < deadline { try await Task.sleep(for: .milliseconds(10)) }
        XCTAssertEqual(panel.addition, .added); XCTAssertFalse(panel.canAddSubscription)
        XCTAssertTrue(panel.progress.isEmpty)
        XCTAssertTrue(panel.activationText.isEmpty); XCTAssertEqual(store.configurations.count, 4)
        let requests = await stub.requests
        XCTAssertEqual(requests.count, 1)
        XCTAssertEqual(try PanelJSON.parse(requests[0].1, limit: 16384).field("code").text(), "QWRT")
        let sub = try XCTUnwrap(panel.subscriptions.first)
        let ids = store.configurations.map(\.id)
        panel.refresh(sub)
        while panel.busy && Date() < deadline { try await Task.sleep(for: .milliseconds(10)) }
        XCTAssertFalse(panel.busy); XCTAssertNil(panel.error)
        XCTAssertEqual(panel.subscriptions.first?.id, sub.id)
        XCTAssertEqual(panel.subscriptions.first?.token, sub.token)
        XCTAssertEqual(store.configurations.map(\.id), ids)
        XCTAssertEqual(store.splitTunneling, try PanelFixture.settings.splitTunneling.validated())
        let count = await stub.requests.count; XCTAssertEqual(count, 2)
    }

    @MainActor func testSubscriptionAdditionFailureAndCancellationRetainAcceptedState() async throws {
        let stub = PanelStub(PanelFixture(), failures: [400]), v = vault()
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let store = SimpleStore(fileURL: dir.appendingPathComponent("profiles.json"), defaults: UserDefaults(suiteName: UUID().uuidString)!, panelVault: v)
        let panel = PanelManager(store: store, client: PanelClient(vault: v, exchange: stub, pause: { _ in }), activationService: PanelServiceOrigins(primary: stub.fixture.trust))
        panel.updateSubscriptionKey("qwrt"); panel.addSubscription()
        var deadline = Date().addingTimeInterval(5)
        while panel.busy && Date() < deadline { try await Task.sleep(for: .milliseconds(10)) }
        guard case .failed(let message) = panel.addition else { return XCTFail("Expected a retryable inline error") }
        XCTAssertTrue(message.contains("being prepared")); XCTAssertNil(panel.error)
        XCTAssertTrue(panel.progress.isEmpty)
        XCTAssertTrue(panel.canAddSubscription); XCTAssertTrue(panel.subscriptions.isEmpty)
        panel.addSubscription()
        while panel.busy && Date() < deadline { try await Task.sleep(for: .milliseconds(10)) }
        XCTAssertEqual(panel.addition, .added)
        let accepted = try v.snapshot()
        let profiles = store.configurations
        await stub.setBlock()
        panel.prepareSubscriptionForm(); panel.updateSubscriptionKey("AAAA"); panel.addSubscription()
        deadline = Date().addingTimeInterval(5)
        while await stub.requests.count < 3 && Date() < deadline { try await Task.sleep(for: .milliseconds(10)) }
        panel.cancel()
        while panel.busy && Date() < deadline { try await Task.sleep(for: .milliseconds(10)) }
        XCTAssertFalse(panel.busy); XCTAssertEqual(panel.addition, .idle)
        XCTAssertTrue(panel.progress.isEmpty)
        XCTAssertTrue(panel.canAddSubscription); XCTAssertNil(panel.error)
        XCTAssertEqual(try v.snapshot(), accepted); XCTAssertEqual(store.configurations, profiles)
    }

    @MainActor func testOfficialLinksAcceptBothOriginsAndRejectForeignHostsOrPins() throws {
        let service = PanelServiceOrigins(primary: PanelFixture().trust, alternateAPIs: ["https://backup.example.test/v1"])
        let store = SimpleStore(fileURL: FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString),
                                defaults: UserDefaults(suiteName: UUID().uuidString)!, panelVault: vault())
        let manager = PanelManager(store: store, activationService: service)
        func open(_ api: String, key: String, kid: String) throws {
            var link = URLComponents(string: "tndtun://activate")!
            link.queryItems = [URLQueryItem(name: "code", value: "QWRT"), URLQueryItem(name: "api", value: api),
                               URLQueryItem(name: "kid", value: kid), URLQueryItem(name: "key", value: key)]
            manager.receive(try XCTUnwrap(link.url))
        }
        for api in [service.primary.api] + service.alternateAPIs {
            try open(api, key: service.primary.publicKey, kid: service.primary.keyID)
            XCTAssertTrue(manager.canAddSubscription)
        }
        for (api, key, kid) in [("https://other.example/v1", service.primary.publicKey, service.primary.keyID),
                                (service.primary.api, PanelFixture().trust.publicKey, service.primary.keyID),
                                (service.primary.api, service.primary.publicKey, "0000000000000000")] {
            try open(api, key: key, kid: kid)
            XCTAssertFalse(manager.canAddSubscription)
            XCTAssertTrue(manager.activationText.isEmpty)
        }
    }

    func testReactivationByNewOriginKeepsLegacyDeviceOwnerAndProfileGrants() async throws {
        let fixture = PanelFixture(), store = vault()
        var old = fixture.trust
        old.api = "https://old.example.test/v1"
        let service = PanelServiceOrigins(primary: fixture.trust, alternateAPIs: [old.api])
        let exchange = PanelStub(fixture)
        let client = PanelClient(vault: store, exchange: exchange, serviceOverride: service)
        try await client.activate(PanelActivation(code: "QWRT", trust: old), name: "Phone", baseline: PanelFixture.settings, manualIDs: [])
        let original = try store.snapshot()
        let sub = try XCTUnwrap(original.subscriptions.first)
        let grant = try XCTUnwrap(sub.package.profiles[0].configuration(subscriptionID: sub.id).profile.panelAccess)

        try await client.activate(PanelActivation(code: "QWRT", trust: fixture.trust), name: "Phone", baseline: PanelFixture.settings, manualIDs: [])
        try await client.sync(sub, baseline: PanelFixture.settings, manualIDs: [])
        let current = try store.snapshot()
        XCTAssertEqual(current.subscriptions.map(\.id), [sub.id])
        XCTAssertEqual(current.subscriptions.first?.token, sub.token)
        XCTAssertEqual(current.records, original.records)
        XCTAssertEqual(current.globalSettings, original.globalSettings)
        XCTAssertEqual(current.activeSettingsOwner, original.activeSettingsOwner)
        XCTAssertEqual(current.installationID, original.installationID)
        XCTAssertTrue(try store.permits(grant, now: 1))
        var foreign = old
        foreign.api = "https://unrelated.example/v1"
        XCTAssertEqual(service.endpoints(for: foreign), [foreign])
        do {
            try await client.activate(PanelActivation(code: "QWRT", trust: foreign), name: "Phone", baseline: PanelFixture.settings, manualIDs: [])
            XCTFail("A different source cannot take over the existing profiles")
        } catch is PanelFailure {}
        XCTAssertEqual(try store.snapshot(), current)
    }

    func testDeletedLegacySubscriptionIsNotRecreatedByPendingAliasActivation() async throws {
        let fixture = PanelFixture(), store = vault()
        var legacy = fixture.trust
        legacy.api = "https://old.example.test/v1"
        let service = PanelServiceOrigins(primary: fixture.trust, alternateAPIs: [legacy.api])
        let original = PanelClient(vault: store, exchange: PanelStub(fixture), serviceOverride: service)
        try await original.activate(PanelActivation(code: "QWRT", trust: legacy), name: "Phone", baseline: PanelFixture.settings, manualIDs: [])
        let id = try XCTUnwrap(store.snapshot().subscriptions.first?.id)
        let inFlight = PanelClient(vault: store, exchange: PanelStub(fixture, failures: [503]), pause: { _ in
            try store.transaction { $0.remove(id) }
        }, serviceOverride: service)
        do {
            try await inFlight.activate(PanelActivation(code: "QWRT", trust: fixture.trust), name: "Phone", baseline: PanelFixture.settings, manualIDs: [])
            XCTFail("The late activation must respect the deletion under the previous address")
        } catch let error as PanelFailure {
            XCTAssertTrue(error.message.contains("removed"))
        }
        XCTAssertTrue(try store.snapshot().subscriptions.isEmpty)
    }

    func testLinksRejectDuplicateUnknownIncompleteAndUntrustedPins() throws {
        let f = PanelFixture(); let code = String(repeating: "A", count: 26)
        let text = "tndtun://activate?api=https%3A%2F%2Fpanel.example.test%2Fv1&code=\(code)&key=\(f.trust.publicKey)&kid=\(f.trust.keyID)"
        XCTAssertEqual(try PanelContract.activation(text, bootstrap: f.trust).trust, f.trust)
        XCTAssertEqual(try PanelContract.activation("aaaaaa-aaaaaa-aaaaaa-aaaaaaaa", bootstrap: f.trust).code, code)
        for bad in [text + "&code=" + code, text + "&%63ode=" + code, text + "&other=x", text.replacingOccurrences(of: "&kid=", with: "&bad="), text.replacingOccurrences(of: "https%3A", with: "http%3A")] {
            XCTAssertThrowsError(try PanelContract.activation(bad, bootstrap: f.trust))
        }
        XCTAssertEqual(try PanelContract.api("https://EXAMPLE.test:443/v1/"), "https://example.test/v1")
        for bad in ["http://example.test/v1", "https://user@example.test/v1", "https://example.test/v1?x=1", "https://example.test/", "https://example.test/v1#x"] { XCTAssertThrowsError(try PanelContract.api(bad)) }
    }
    func testPackageRejectsStaleWrongIdentityNonceAndMalformedFields() throws {
        let f = PanelFixture(); let p = try f.package()
        let previous = PanelSubscription(id: f.trust.api + "#" + f.device, trust: f.trust, token: "token", package: p, lastSync: 0)
        for (field, value): (String, Any) in [("revision", 2), ("revision", 3.5), ("schema_version", true), ("expires_at", -1), ("nonce", "other"), ("device_id", f.clientID), ("client_id", f.device), ("sync_after_seconds", 0), ("status", "unknown")] {
            var payload = try f.payload(); payload[field] = value
            XCTAssertThrowsError(try PanelContract.verify(f.envelope(payload), trust: f.trust, nonce: "nonce", deviceID: f.device, previous: previous), field)
        }
        XCTAssertNoThrow(try PanelContract.verify(f.envelope(f.payload()), trust: f.trust, nonce: "nonce", deviceID: f.device, previous: previous))
        var payload = try f.payload(); payload["profiles"] = Array(repeating: (payload["profiles"] as! [[String: Any]])[0], count: 2)
        XCTAssertThrowsError(try PanelContract.verify(f.envelope(payload), trust: f.trust, nonce: "nonce", deviceID: f.device))
        payload = try f.payload(); payload["status"] = "revoked"
        XCTAssertThrowsError(try PanelContract.verify(f.envelope(payload), trust: f.trust, nonce: "nonce", deviceID: f.device))
    }
    func testVaultAtomicityTombstonesExpiryAndRevocationWithoutRecovery() throws {
        let f = PanelFixture(), v = vault(); var p = try f.package(); p.expiresAt = 200
        let id = f.trust.api + "#" + f.device
        try v.transaction { try $0.accept(p, trust: f.trust, token: "secret-token", expectedEpoch: 0, activation: true, manualIDs: [], baseline: PanelFixture.settings, now: 100) }
        let row = try p.profiles[0].configuration(subscriptionID: id, expiresAt: 200)
        XCTAssertNoThrow(try PanelAccess.require(row.profile.panelAccess, vault: v, now: 199))
        XCTAssertThrowsError(try PanelAccess.require(row.profile.panelAccess, vault: v, now: 200))
        // A signed expiry extension takes effect without restarting a working
        // tunnel or trusting the stale expiry carried in its original grant.
        var extended = p; extended.expiresAt = 300
        try v.transaction { try $0.accept(extended, trust: f.trust, token: "secret-token", expectedEpoch: 0, activation: false, manualIDs: [], baseline: PanelFixture.settings, now: 150) }
        XCTAssertNoThrow(try PanelAccess.require(row.profile.panelAccess, vault: v, now: 250))
        XCTAssertThrowsError(try PanelAccess.require(row.profile.panelAccess, vault: v, now: 300))
        let before = try v.snapshot()
        XCTAssertThrowsError(try v.transaction { state in
            state.installationID = "not-committed"
            throw PanelFailure("test failure")
        })
        XCTAssertEqual(try v.snapshot(), before)
        var revoked = p; revoked.status = "revoked"; revoked.profiles = []; revoked.settings = nil
        try v.transaction { try $0.accept(revoked, trust: f.trust, token: "secret-token", expectedEpoch: 0, activation: false, manualIDs: [], baseline: PanelFixture.settings, now: 101) }
        XCTAssertThrowsError(try PanelAccess.require(row.profile.panelAccess, vault: v, now: 150))
        try v.transaction { $0.remove(id) }
        XCTAssertThrowsError(try v.transaction { try $0.accept(p, trust: f.trust, token: "token", expectedEpoch: 0, activation: true, manualIDs: [], baseline: PanelFixture.settings, now: 102) })
        try v.transaction { try $0.accept(p, trust: f.trust, token: "token", expectedEpoch: 1, activation: true, manualIDs: [], baseline: PanelFixture.settings, now: 103) }
        XCTAssertEqual(try v.snapshot().subscriptions.count, 1)
        XCTAssertNoThrow(try PanelAccess.require(nil, vault: vault(), now: 1))
    }
    func testGlobalSettingsOwnerDoesNotFollowAnotherSubscriptionRefresh() throws {
        let f = PanelFixture(); var state = PanelVaultState(); let p = try f.package()
        try state.accept(p, trust: f.trust, token: "a", expectedEpoch: 0, activation: true, manualIDs: [], baseline: PanelFixture.settings, now: 0)
        var other = p; other.deviceID = f.clientID; other.profiles = []; other.settings?.turnCheckInterval = 80
        try state.accept(other, trust: f.trust, token: "b", expectedEpoch: 0, activation: true, manualIDs: [], baseline: PanelFixture.settings, now: 1)
        XCTAssertEqual(state.globalSettings?.turnCheckInterval, 80)
        var updated = p; updated.revision += 1; updated.settings?.turnCheckInterval = 90
        try state.accept(updated, trust: f.trust, token: "a", expectedEpoch: 0, activation: false, manualIDs: [], baseline: PanelFixture.settings, now: 2)
        XCTAssertEqual(state.globalSettings?.turnCheckInterval, 80)
        state.remove(f.trust.api + "#" + other.deviceID)
        XCTAssertEqual(state.globalSettings?.turnCheckInterval, 90)
    }
    func testColdExtensionAccessReadsOnlyAuthenticatedRecordForLargePackage() throws {
        let f = PanelFixture(), directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let key = Data(repeating: 91, count: 32), v = PanelVault(directory: directory, key: key)
        var packet = try f.package()
        let source = packet.profiles[0]
        packet.profiles = (0..<1000).map { index in var row = source; row.id = String(format: "32345678-1234-1234-1234-%012d", index); return row }
        packet.settings?.splitTunneling.bypassEntries = (0..<10_000).map { SplitTunnelEntry(address: "site\($0).example.test", networks: ["203.0.113.0/24"]) }
        let id = f.trust.api + "#" + f.device
        try v.transaction { try $0.accept(packet, trust: f.trust, token: "token", expectedEpoch: 0, activation: true, manualIDs: [], baseline: PanelFixture.settings, now: 1) }
        for index in [0, 500, 999] {
            let grant = try XCTUnwrap(packet.profiles[index].configuration(subscriptionID: id).profile.panelAccess)
            XCTAssertNoThrow(try PanelAccess.require(grant, vault: PanelVault(directory: directory, key: key)))
        }
        let grant = try XCTUnwrap(packet.profiles[500].configuration(subscriptionID: id).profile.panelAccess)
        let file = directory.appendingPathComponent("panel-state.enc")
        var bytes = try Data(contentsOf: file)
        XCTAssertEqual(bytes.prefix(8), PanelAccessIndex.magic)
        // Damage the large settings body. Its independently authenticated access
        // record remains usable, proving the extension does not hydrate the body.
        bytes[bytes.count - 1] ^= 1
        try bytes.write(to: file, options: .atomic)
        XCTAssertThrowsError(try PanelVault(directory: directory, key: key).snapshot())
        XCTAssertNoThrow(try PanelAccess.require(grant, vault: PanelVault(directory: directory, key: key)))
        // Forging the access record itself must fail closed.
        let wanted = PanelAccessIndex.lookupKey(grant)
        var offset = 12
        while bytes.subdata(in: offset..<(offset + 32)) != wanted { offset += PanelAccessIndex.recordSize }
        bytes[offset + 50] ^= 1
        try bytes.write(to: file, options: .atomic)
        XCTAssertThrowsError(try PanelAccess.require(grant, vault: PanelVault(directory: directory, key: key)))
    }

    func testCrossProcessLeaseAndEncryptedPersistence() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let key = Data(repeating: 4, count: 32), a = PanelVault(directory: dir, key: key), b = PanelVault(directory: dir, key: key)
        let installation = try a.installationID()
        XCTAssertEqual(try b.installationID(), installation)
        var lease: PanelRequestLease? = try a.requestLease()
        XCTAssertThrowsError(try b.requestLease())
        withExtendedLifetime(lease) {}; lease = nil
        XCTAssertNoThrow(try b.requestLease())
        let raw = try Data(contentsOf: dir.appendingPathComponent("panel-state.enc"))
        XCTAssertFalse(String(decoding: raw, as: UTF8.self).contains(installation))
        XCTAssertThrowsError(try PanelVault(directory: dir, key: Data(repeating: 5, count: 32)).snapshot())
    }
    func testRetryReusesInstallationNonceAnd401RetainsAcceptedAccess() async throws {
        let f = PanelFixture(), v = vault(), stub = PanelStub(PanelFixture(), failures: [503])
        // Use the same fixture's signing pin as the stub.
        let server = stub.fixture
        let client = PanelClient(vault: v, exchange: stub, pause: { _ in })
        let input = try PanelContract.activation(" q-wr t ", bootstrap: server.trust)
        try await client.activate(input, name: "Test phone", baseline: PanelFixture.settings, manualIDs: [])
        let requests = await stub.requests
        XCTAssertEqual(requests.count, 2); XCTAssertEqual(requests[0].1, requests[1].1)
        XCTAssertEqual(try PanelJSON.parse(requests[0].1, limit: 16384).field("code").text(), "QWRT")
        let previous = try XCTUnwrap(v.snapshot().subscriptions.first)
        let failure = PanelStub(server, failures: [401])
        do { try await PanelClient(vault: v, exchange: failure).sync(previous, baseline: PanelFixture.settings, manualIDs: []); XCTFail("401") } catch {}
        let retained = try XCTUnwrap(v.snapshot().subscriptions.first)
        XCTAssertTrue(retained.needsActivation); XCTAssertEqual(retained.package, previous.package)
        XCTAssertTrue(retained.accessAllowed(now: Int64(Date().timeIntervalSince1970)))
        _ = f
    }
    func testCancellationAndLateDeletionCannotCommit() async throws {
        let f = PanelFixture(), v = vault(), stub = PanelStub(PanelFixture())
        let server = stub.fixture; await stub.setBlock()
        let task = Task { try await PanelClient(vault: v, exchange: stub).activate(PanelActivation(code: String(repeating: "A", count: 26), trust: server.trust), name: "Phone", baseline: PanelFixture.settings, manualIDs: []) }
        try await Task.sleep(for: .milliseconds(20)); task.cancel()
        do { try await task.value; XCTFail("cancelled") } catch {}
        XCTAssertTrue(try v.snapshot().subscriptions.isEmpty)
        _ = f
    }
    @MainActor func testBackupTransfersCredentialsAsManualWithoutPanelIdentity() throws {
        let f = PanelFixture(), v = vault(), p = try f.package()
        try v.transaction { try $0.accept(p, trust: f.trust, token: "secret-token", expectedEpoch: 0, activation: true, manualIDs: [], baseline: PanelFixture.settings, now: 100) }
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let defaults = UserDefaults(suiteName: UUID().uuidString)!
        let store = SimpleStore(fileURL: directory.appendingPathComponent("manual.json"), defaults: defaults, panelVault: v)
        XCTAssertEqual(store.configurations.count, 4)
        let bytes = try store.backup().encoded(), text = String(decoding: bytes, as: UTF8.self)
        for forbidden in ["secret-token", "subscriptionID", "device_id", "installation_id", "panel-bootstrap", "activeSettingsOwner"] { XCTAssertFalse(text.contains(forbidden), forbidden) }
        let backup = try ApplicationBackup.decode(bytes)
        XCTAssertTrue(backup.profiles.allSatisfy { $0.managed == nil })
        try store.restore(backup)
        XCTAssertEqual(store.configurations.count, 8)
        XCTAssertEqual(Set(store.configurations.map(\.id)).count, 8)
        XCTAssertEqual(try v.snapshot().subscriptions.count, 1)
        XCTAssertEqual(store.splitTunneling, try PanelFixture.settings.splitTunneling.validated())
        XCTAssertThrowsError(try store.save(XCTUnwrap(store.configurations.first { $0.managed != nil })))
    }
    func testSharedKeychainCanEncryptAndReloadAnIsolatedVault() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let a = PanelVault(directory: directory), id = try a.installationID()
        XCTAssertEqual(try PanelVault(directory: directory).installationID(), id)
    }
    @MainActor func testManualQueueCoalescesAndSerializesWithoutStartupRequests() async throws {
        let f = PanelFixture(), v = vault(), stub = PanelStub(PanelFixture())
        let server = stub.fixture
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let store = SimpleStore(fileURL: dir.appendingPathComponent("profiles.json"), defaults: UserDefaults(suiteName: UUID().uuidString)!, panelVault: v)
        let panel = PanelManager(store: store, client: PanelClient(vault: v, exchange: stub, pause: { _ in }))
        panel.reload(); panel.reload()
        let initial = await stub.requests.count; XCTAssertEqual(initial, 0)
        let input = PanelActivation(code: String(repeating: "A", count: 26), trust: server.trust)
        panel.activate(input, name: "Phone")
        XCTAssertEqual(panel.pendingCount, 0)
        let untrustedRequests = await stub.requests.count; XCTAssertEqual(untrustedRequests, 0)
        XCTAssertNotNil(panel.error); panel.error = nil
        for _ in 0..<15 { panel.activate(input, name: "Phone", trustConfirmed: true) }
        XCTAssertEqual(panel.pendingCount, 1)
        // A different request must wait, and reuse the committed installation.
        panel.activate(PanelActivation(code: String(repeating: "B", count: 26), trust: server.trust), name: "Phone", trustConfirmed: true)
        XCTAssertEqual(panel.pendingCount, 2)
        let deadline = Date().addingTimeInterval(5)
        while panel.busy && Date() < deadline { try await Task.sleep(for: .milliseconds(10)) }
        XCTAssertFalse(panel.busy); XCTAssertNil(panel.error)
        let requests = await stub.requests
        XCTAssertEqual(requests.count, 2)
        let ids = try requests.map { try PanelJSON.parse($0.1, limit: 16384).field("installation_id").text() }
        XCTAssertEqual(Set(ids).count, 1)
        XCTAssertEqual(store.configurations.count, 4)
        _ = f
    }

    @MainActor func testPanelDNSPortsAndIPv6UseTCPAndBaselineCanBeRestored() throws {
        let runtime = AppStore()
        runtime.applyPanelDNS(["[2001:db8::53]:5353", "1.1.1.1:53"])
        XCTAssertEqual(runtime.settings.remoteDNS, "tcp://[2001:db8::53]:5353")
        XCTAssertEqual(runtime.settings.vpnDNS, ["2001:db8::53", "1.1.1.1"])
        var profile = VPNProfile(); profile.kind = .socks; profile.address = "127.0.0.1"; profile.port = 9000
        let raw = XrayConfigurationBuilder.build(profile: profile, settings: runtime.settings)
        let root = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any])
        let servers = try XCTUnwrap((root["dns"] as? [String: Any])?["servers"] as? [String])
        XCTAssertTrue(servers.allSatisfy { $0.hasPrefix("tcp://") })
        XCTAssertTrue(servers.contains("tcp://[2001:db8::53]:53"))
        runtime.applyPanelDNS([])
        XCTAssertEqual(runtime.settings.remoteDNS, AppSettings().remoteDNS)
        XCTAssertEqual(runtime.settings.vpnDNS, AppSettings().vpnDNS)
    }

    func testResolverCandidatesPreferPhysicalLTEAndGoogleWiFiAndBoundCount() {
        let dns = PanelDNS(domain: "dns.test", publicKey: "", resolver: "1.1.1.1:53", savedResolvers: ["8.8.8.8:53"])
        XCTAssertEqual(PanelResolverCandidates.values(dns, discovered: ["10.0.0.1:53"], wifi: false).first, "10.0.0.1:53")
        XCTAssertEqual(PanelResolverCandidates.values(dns, discovered: ["10.0.0.1:53"], wifi: true).first, "https://dns.google/dns-query")
        XCTAssertLessThanOrEqual(PanelResolverCandidates.values(dns, discovered: (1...20).map { "10.0.0.\($0):53" }, wifi: true).count, 4)
    }

    func testLiveDirectAndDNSTTFallbackOnIsolatedInstallation() async throws {
        #if !targetEnvironment(macCatalyst)
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let fixtureURL = docs.appendingPathComponent("panel-live-fixture.json")
        guard FileManager.default.fileExists(atPath: fixtureURL.path) else { throw XCTSkip("Requires authorized private fixture; see docs/PANEL_SYNC.md") }
        let fixture = try PanelJSON.parse(Data(contentsOf: fixtureURL), limit: 16384)
        guard Bundle.main.url(forResource: "panel-bootstrap", withExtension: "json") != nil else {
            throw XCTSkip("This test requires a configured local panel.")
        }
        let bootstrap = try PanelContract.bundled()
        let input = try PanelContract.activation(fixture.field("activation_link").text(8192), bootstrap: bootstrap)
        XCTAssertTrue(bootstrap.sameSource(input.trust))
        let liveVault = PanelVault(directory: docs.appendingPathComponent("panel-live-vault"), key: Data(repeating: 79, count: 32))
        // Allow the host's initial read-only UI projection to finish before
        // observing settings. JSON key ordering is not a configuration change.
        try await Task.sleep(for: .milliseconds(600))
        let beforeRuntime = KindlyTurnRuntime.statusData()
        #if targetEnvironment(simulator)
        let managers: [NETunnelProviderManager] = [] // NetworkExtension preferences IPC is unavailable in Simulator.
        #else
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()
        #endif
        let activeManagers = managers.filter { [.connected, .reasserting].contains($0.connection.status) }
        let beforeSettings = try AppGroup.defaults.data(forKey: AppGroup.settingsKey).map { try JSONDecoder().decode(AppSettings.self, from: $0) }
        let beforeActiveConfiguration = AppGroup.activeConfigURL.flatMap { try? Data(contentsOf: $0) }
        let beforeProfile = AppGroup.defaults.string(forKey: AppGroup.activeProfileKey)
        let baselineHTTP = activeManagers.isEmpty ? false : await ordinaryHTTPSWorks()
        if ProcessInfo.processInfo.environment["TNDTUN_REQUIRE_ACTIVE_VPN"] == "1" {
            XCTAssertFalse(activeManagers.isEmpty, "This opt-in check requires an established device VPN")
            XCTAssertTrue(baselineHTTP, "Establish ordinary internet access before checking bootstrap isolation")
        }
        var devices = Set<String>()
        for forceDNS in [false, true] {
            // Keep checking throughout pool startup, manifest and both package
            // requests, rather than finishing one HTTP request before DNSTT is ready.
            let ordinaryTraffic: Task<Int, Never>? = forceDNS && baselineHTTP ? Task {
                var successes = 0
                while !Task.isCancelled {
                    let worked = await ordinaryHTTPSWorks()
                    if Task.isCancelled { break }
                    if !worked { return -1 }
                    successes += 1
                    do { try await Task.sleep(for: .seconds(1)) } catch { break }
                }
                return successes
            } : nil
            defer { ordinaryTraffic?.cancel() }
            let routeLog = PanelRouteLog()
            let exchange = PanelNativeExchange(forceDNS: forceDNS, readSystemDNS: { false }, progress: { await routeLog.route($0) })
            let client = PanelClient(vault: liveVault, exchange: exchange)
            let started = Date()
            try await client.activate(input, name: "iOS simulator integration", baseline: PanelFixture.settings, manualIDs: [])
            let transport = await exchange.lastTransport
            XCTAssertTrue(["direct", "dnstt"].contains(transport))
            if forceDNS { XCTAssertEqual(transport, "dnstt") }
            let sub = try XCTUnwrap(liveVault.snapshot().subscriptions.first)
            XCTAssertEqual(sub.package.profiles.count, 2)
            devices.insert(sub.package.deviceID)
            try await client.sync(sub, baseline: PanelFixture.settings, manualIDs: [])
            let routes = await routeLog.routes
            XCTAssertEqual(routes.first, forceDNS ? .dns : .direct)
            if forceDNS { XCTAssertTrue(routes.allSatisfy { $0 == .dns }) }
            let syncTransport = await exchange.lastTransport
            print("Panel live \(forceDNS ? "forced DNS" : "normal") activation=\(transport), sync=\(syncTransport), stages=\(routes), elapsed=\(String(format: "%.2f", Date().timeIntervalSince(started)))s")
            XCTAssertEqual(PanelTransportRuntime.activeRequests, 0)
            XCTAssertEqual(KindlyTurnRuntime.statusData(), beforeRuntime)
            XCTAssertEqual(AppGroup.defaults.string(forKey: AppGroup.activeProfileKey), beforeProfile)
            ordinaryTraffic?.cancel()
            if let ordinaryTraffic {
                let successes = await ordinaryTraffic.value
                XCTAssertGreaterThan(successes, 1, "Ordinary HTTPS must keep using the existing system VPN throughout panel DNSTT")
                print("Ordinary system HTTPS probes completed during DNSTT: \(successes)")
            }
        }
        XCTAssertEqual(devices.count, 1, "Repeated activation must not take a new device slot")
        var wrongPin = bootstrap; wrongPin.keyID = "0000000000000000"
        do {
            _ = try await PanelNativeExchange(forceDNS: true).post(trust: wrongPin, dns: bootstrap.dns, path: "activate", body: Data("{}".utf8), token: nil, deadline: Date().addingTimeInterval(192))
            XCTFail("A mismatched manifest must reject the route before the credential request")
        } catch let failure as PanelFailure { XCTAssertTrue(failure.message.contains("No credentials")) }
        XCTAssertEqual(PanelTransportRuntime.activeRequests, 0)
        let cancelled = Task {
            try await PanelNativeExchange(forceDNS: true).post(trust: bootstrap, dns: bootstrap.dns, path: "activate", body: Data("{}".utf8), token: nil, deadline: Date().addingTimeInterval(192))
        }
        try await Task.sleep(for: .milliseconds(200)); cancelled.cancel()
        do { _ = try await cancelled.value; XCTFail("Cancellation") } catch is CancellationError {} catch { XCTFail("Unexpected cancellation error type") }
        XCTAssertEqual(PanelTransportRuntime.activeRequests, 0)
        XCTAssertEqual(KindlyTurnRuntime.statusData(), beforeRuntime)
        XCTAssertEqual(try AppGroup.defaults.data(forKey: AppGroup.settingsKey).map { try JSONDecoder().decode(AppSettings.self, from: $0) }, beforeSettings)
        XCTAssertEqual(AppGroup.activeConfigURL.flatMap { try? Data(contentsOf: $0) }, beforeActiveConfiguration)
        for manager in activeManagers { XCTAssertTrue([.connected, .reasserting].contains(manager.connection.status)) }
        print("Panel live checks completed: normal direct-first route and real DNSTT, unchanged identity, manifest rejection and cancellation; preserved existing VPN sessions: \(activeManagers.count), ordinary HTTPS during DNSTT checked: \(baselineHTTP)")
        #else
        throw XCTSkip("Live panel checks run only inside the simulator; never change the host Mac VPN")
        #endif
    }
    private func ordinaryHTTPSWorks() async -> Bool {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 12; config.timeoutIntervalForResource = 15
        let session = URLSession(configuration: config); defer { session.invalidateAndCancel() }
        do {
            let (_, response) = try await session.data(from: URL(string: "https://www.gstatic.com/generate_204")!)
            return (response as? HTTPURLResponse)?.statusCode == 204
        } catch { return false }
    }

}
