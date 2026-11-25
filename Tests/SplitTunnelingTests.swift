import XCTest
import SwiftyXrayKit
@testable import TnDtun

final class SplitTunnelingTests: XCTestCase {
    func testTemporaryFullTunnelPreservesBothListsPushAndIPv6() throws {
        for mode in [SplitTunnelMode.bypassSelected, .tunnelSelected] {
            for ipv6 in [false, true] {
                var saved = AppSettings(); saved.ipv6Enabled = ipv6
                saved.splitTunneling = SplitTunnelSettings(mode: mode,
                    bypassEntries: [SplitTunnelEntry(address: "203.0.113.0/24")],
                    tunnelEntries: [SplitTunnelEntry(address: "2001:db8::/32")],
                    pushNotifications: PushNotificationSettings(apple: true, google: true))
                let full = TemporaryFullTunnelPolicy.applying(to: saved, isTURN: true, isDNS: false, isAmnezia: false, full: true)
                XCTAssertEqual(full.splitTunneling?.mode, .disabled)
                XCTAssertEqual(full.splitTunneling?.bypassEntries, saved.splitTunneling?.bypassEntries)
                XCTAssertEqual(full.splitTunneling?.tunnelEntries, saved.splitTunneling?.tunnelEntries)
                XCTAssertEqual(full.splitTunneling?.pushNotifications, saved.splitTunneling?.pushNotifications)
                XCTAssertEqual(full.ipv6Enabled, ipv6)
                XCTAssertEqual(TemporaryFullTunnelPolicy.applying(to: saved, isTURN: true, isDNS: false, isAmnezia: false, full: false), saved)
                XCTAssertEqual(TemporaryFullTunnelPolicy.applying(to: saved, isTURN: false, isDNS: false, isAmnezia: true, full: false), saved)
                XCTAssertEqual(TemporaryFullTunnelPolicy.applying(to: saved, isTURN: false, isDNS: false, isAmnezia: true, full: true), full)
                saved.amneziaSplitEnabled = false
                XCTAssertEqual(TemporaryFullTunnelPolicy.applying(to: saved, isTURN: false, isDNS: false, isAmnezia: true, full: false).splitTunneling?.mode, .disabled)
                XCTAssertEqual(TemporaryFullTunnelPolicy.applying(to: saved, isTURN: true, isDNS: false, isAmnezia: false, full: false), saved)
                XCTAssertEqual(TemporaryFullTunnelPolicy.applying(to: saved, isTURN: true, isDNS: true, isAmnezia: false, full: false).splitTunneling?.mode, .disabled)
            }
        }
    }

    @MainActor func testTemporaryOptionsSurviveBackupAndLegacyImport() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let name = "full-tunnel-tests-" + UUID().uuidString
        let defaults = UserDefaults(suiteName: name)!
        defer { defaults.removePersistentDomain(forName: name); try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("profiles.json")
        let store = SimpleStore(fileURL: file, defaults: defaults)
        XCTAssertTrue(store.amneziaSplitEnabled)
        XCTAssertNil(defaults.object(forKey: "simple.amneziaSplitEnabled"))
        store.amneziaSplitEnabled = false
        store.fullTunnelMinutes = 0
        XCTAssertFalse(SimpleStore(fileURL: file, defaults: defaults).amneziaSplitEnabled)
        let backup = try store.backup()
        let restored = try ApplicationBackup.decode(backup.encoded())
        XCTAssertEqual(restored.amneziaSplitEnabled, false)
        XCTAssertEqual(restored.fullTunnelMinutes, 0)
        store.amneziaSplitEnabled = true
        try store.restore(restored)
        XCTAssertFalse(store.amneziaSplitEnabled)
        var legacy = try XCTUnwrap(JSONSerialization.jsonObject(with: backup.encoded()) as? [String: Any])
        legacy.removeValue(forKey: "amneziaSplitEnabled"); legacy.removeValue(forKey: "fullTunnelMinutes")
        try store.restore(ApplicationBackup.decode(JSONSerialization.data(withJSONObject: legacy)))
        XCTAssertTrue(store.amneziaSplitEnabled)
        XCTAssertEqual(store.fullTunnelMinutes, 15)
        legacy["fullTunnelMinutes"] = -1
        XCTAssertThrowsError(try ApplicationBackup.decode(JSONSerialization.data(withJSONObject: legacy)))
    }

    func testPushOverlayOverridesDirectListsWithoutChangingTheirStoredNetworks() throws {
        for mode in SplitTunnelMode.allCases {
            var settings = AppSettings()
            let before = SplitTunnelSettings(mode: mode, bypassEntries: [SplitTunnelEntry(address: "17.0.0.0/8")],
                tunnelEntries: [SplitTunnelEntry(address: "203.0.113.0/24")], pushNotifications: PushNotificationSettings(apple: true, google: true))
            settings.splitTunneling = before
            let root: [String: Any] = ["routing": ["rules": [["type": "field", "inboundTag": ["probe"], "outboundTag": "proxy"]]],
                                      "dns": ["servers": ["1.1.1.1"]]]
            let applied = SplitTunnelRouting.applying(to: root, settings: settings)
            let rules = try XCTUnwrap((applied["routing"] as? [String: Any])?["rules"] as? [[String: Any]])
            let push = try XCTUnwrap(rules.firstIndex { ($0["ip"] as? [String]) == PushNotificationRouting.appleNetworks })
            let block = try XCTUnwrap(rules.firstIndex { ($0["ip"] as? [String]) == ["::/0"] })
            XCTAssertLessThan(block, push)
            if mode != .disabled {
                let fallback = try XCTUnwrap(rules.firstIndex { $0["network"] as? String == "tcp,udp" })
                XCTAssertLessThan(push, fallback)
            }
            XCTAssertEqual(rules[push]["port"] as? String, "443,5223")
            XCTAssertEqual(rules[push]["network"] as? String, "tcp")
            XCTAssertEqual(rules[push]["outboundTag"] as? String, "proxy")
            XCTAssertTrue(rules.filter { $0["port"] as? String == "5228-5230" }.allSatisfy { ($0["inboundTag"] as? [String]) == ["in_proxy", "kindly-socks"] })
            let dns = try XCTUnwrap(applied["dns"] as? [String: Any])
            let servers = try XCTUnwrap(dns["servers"] as? [Any])
            XCTAssertEqual((servers.first as? [String: Any])?["tag"] as? String, "kindly-dns-push")
            XCTAssertEqual((servers.first as? [String: Any])?["skipFallback"] as? Bool, true)
            XCTAssertEqual(settings.splitTunneling, before)
            XCTAssertEqual(try JSONDecoder().decode(SplitTunnelSettings.self, from: JSONEncoder().encode(before)), before)
        }
    }

    func testPushSwitchesAreIndependentAndAbsentInOlderSettings() throws {
        let old = Data("{\"mode\":\"disabled\",\"bypassEntries\":[],\"tunnelEntries\":[]}".utf8)
        XCTAssertNil(try JSONDecoder().decode(SplitTunnelSettings.self, from: old).pushNotifications)
        XCTAssertTrue(PushNotificationRouting.rules(PushNotificationSettings(), tags: ["in_proxy"]).isEmpty)
        XCTAssertFalse(PushNotificationRouting.domains(PushNotificationSettings(apple: true)).contains("full:mtalk.google.com"))
        XCTAssertFalse(PushNotificationRouting.domains(PushNotificationSettings(google: true)).contains("domain:push.apple.com"))
    }

    func testPushNativeConfigurations() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("push-routing-build41")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        for mode in SplitTunnelMode.allCases {
            for ipv6 in [false, true] {
                var settings = AppSettings(); settings.ipv6Enabled = ipv6
                settings.splitTunneling = SplitTunnelSettings(mode: mode,
                    bypassEntries: [SplitTunnelEntry(address: "17.0.0.0/8")],
                    tunnelEntries: [SplitTunnelEntry(address: "8.8.8.0/24")],
                    pushNotifications: PushNotificationSettings(apple: true, google: true))
                var profile = VPNProfile(); profile.kind = .socks; profile.address = "127.0.0.1"; profile.port = 9004
                let baseline = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(XrayConfigurationBuilder.build(profile: profile, settings: settings).utf8)) as? [String: Any])
                let applied = TunnelConfiguration.applying(to: baseline, settings: settings, isTURN: false)
                let outbounds = try XCTUnwrap(applied["outbounds"] as? [[String: Any]])
                XCTAssertEqual(outbounds.filter { $0["protocol"] as? String == "socks" }.count, 1)
                XCTAssertNil((applied["policy"] as? [String: Any])?["levels"])
                let file = folder.appendingPathComponent("\(mode.rawValue)-\(ipv6).json")
                try JSONSerialization.data(withJSONObject: applied, options: [.sortedKeys]).write(to: file)
                try SwiftyXray.testConfiguration(dataDir: Bundle.main.resourceURL!.path, configPath: file.path)
            }
        }
        print("Push routing fixtures: \(folder.path)")
    }
    func testAppliedRoutingDiagnosticsExposeOnlyCountsAndFingerprints() throws {
        var settings = AppSettings()
        settings.splitTunneling = SplitTunnelSettings(mode: .tunnelSelected,
            tunnelEntries: [SplitTunnelEntry(address: "private.example", networks: ["203.0.113.0/24", "2001:db8::/32"])])
        let root: [String: Any] = ["routing": ["rules": []], "dns": ["servers": ["1.1.1.1"]], "outbounds": [["password": "private-credential"]]]
        let text = SplitTunnelRouting.diagnosticJSON(root: root, settings: settings)
        let value = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any])
        XCTAssertEqual(value["splitMode"] as? String, "tunnelSelected")
        XCTAssertEqual(value["ipv4Zones"] as? Int, 1); XCTAssertEqual(value["ipv6Zones"] as? Int, 1)
        XCTAssertEqual(value["ipv6Enabled"] as? Bool, false)
        XCTAssertEqual((value["networkSHA256"] as? String)?.count, 64)
        for secret in ["private.example", "private-credential", "203.0.113", "2001:db8", "1.1.1.1"] { XCTAssertFalse(text.contains(secret)) }
        XCTAssertEqual(text, SplitTunnelRouting.diagnosticJSON(root: root, settings: settings))
        var changed = settings; changed.splitTunneling?.tunnelEntries[0].networks.append("198.51.100.0/24")
        XCTAssertNotEqual(text, SplitTunnelRouting.diagnosticJSON(root: root, settings: changed))
    }

    func testOpenCCKGroupsPreserveDomainsAndNetworksAndMergeDuplicates() throws {
        let data = Data("""
        {"Example.COM": ["203.0.113.7/24", "203.0.113.0/24", "2001:db8::1/32"],
         "example.com": ["198.51.100.1"], "other.test": ["203.0.113.0/24"]}
        """.utf8)
        let entries = try SplitTunnelImport.json(data)
        XCTAssertEqual(entries.count, 2)
        XCTAssertEqual(entries.first?.address, "example.com")
        XCTAssertEqual(entries.first?.networks, ["198.51.100.1", "2001:db8::/32", "203.0.113.0/24"])
        var split = SplitTunnelSettings(); split.mode = .tunnelSelected; split.tunnelEntries = entries
        XCTAssertTrue(split.domains.isEmpty)
        XCTAssertEqual(split.dnsDomains, ["domain:example.com", "domain:other.test"])
        XCTAssertEqual(split.networks.count, 3)
    }

    func testManualAddressesURLsIPv6CIDRAndFlatJSON() throws {
        let entries = try SplitTunnelImport.manual("https://Example.com/path, *.example.com 203.0.113.9;2001:db8::9/32\n192.168.1.7/24")
        XCTAssertEqual(entries.map(\.address), ["192.168.1.0/24", "2001:db8::/32", "203.0.113.9", "example.com"])
        let flat = try SplitTunnelImport.json(Data("[\"example.com\",\"203.0.113.0/24\"]".utf8))
        XCTAssertEqual(flat.count, 2)
    }

    func testOpenCCKNonDomainGroupLabelsRouteOnlyTheirNetworks() throws {
        let entries = try SplitTunnelImport.json(Data("{\"copilot\": [\"203.0.113.0/24\"], \"jetbrains@cdn\": [\"198.51.100.0/24\"]}".utf8))
        var split = SplitTunnelSettings(); split.mode = .tunnelSelected; split.tunnelEntries = entries
        XCTAssertEqual(entries.count, 2)
        XCTAssertTrue(entries.allSatisfy(\.isNetworkGroup))
        XCTAssertTrue(split.domains.isEmpty)
        XCTAssertEqual(split.networks, ["198.51.100.0/24", "203.0.113.0/24"])
        XCTAssertEqual(try split.validated(), split)
    }

    func testInvalidInputIsRejectedWithoutPartiallyImporting() {
        for raw in ["", "999.1.2.3", "203.0.113.1/33", "2001:db8::1/129", "bad domain", "example.com:443", "bad..test", "geosite:google", "-bad.test", "https://user:password@example.com"] {
            XCTAssertThrowsError(try SplitTunnelImport.manual(raw), raw)
        }
        for raw in ["{}", "[]", "null", "{\"example.com\": 1}", "{\"example.com\": [\"another.test\"]}", "[\"example.com\",\"203.0.113.7/33\"]"] {
            XCTAssertThrowsError(try SplitTunnelImport.json(Data(raw.utf8)), raw)
        }
        XCTAssertThrowsError(try SplitTunnelImport.json(Data(repeating: 32, count: SplitTunnelImport.maximumFileSize + 1)))
    }

    @MainActor func testSeparateListsSurviveSaveCancelAndRestartAndPublishToExtension() throws {
        let name = "split-test-" + UUID().uuidString
        let defaults = UserDefaults(suiteName: name)!
        defer { defaults.removePersistentDomain(forName: name) }
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = SimpleStore(fileURL: directory.appendingPathComponent("profiles.json"), defaults: defaults)
        var split = SplitTunnelSettings(); split.mode = .bypassSelected
        split.bypassEntries = try SplitTunnelImport.manual("direct.test")
        split.tunnelEntries = try SplitTunnelImport.manual("proxy.test")
        try store.saveSplitTunneling(split)
        var draft = store.splitTunneling; draft.setEntries([], for: .bypassSelected)
        XCTAssertEqual(store.splitTunneling.bypassEntries.count, 1) // Cancelling a draft does not mutate the store.
        let restored = SimpleStore(fileURL: directory.appendingPathComponent("profiles.json"), defaults: defaults)
        XCTAssertEqual(restored.splitTunneling, split)
        split.mode = .tunnelSelected
        try restored.saveSplitTunneling(split)
        XCTAssertEqual(restored.splitTunneling.activeEntries.map(\.address), ["proxy.test"])
        XCTAssertEqual(restored.splitTunneling.bypassEntries.map(\.address), ["direct.test"])
        let runtime = AppStore(); runtime.applySplitTunneling(from: restored)
        let published = try JSONDecoder().decode(AppSettings.self, from: XCTUnwrap(AppGroup.defaults.data(forKey: AppGroup.settingsKey)))
        XCTAssertEqual(published.splitTunneling, split)
        XCTAssertEqual(published.amneziaSplitEnabled, true)
        let old = try JSONSerialization.jsonObject(with: JSONEncoder().encode(AppSettings())) as! [String: Any]
        XCTAssertNil(try JSONDecoder().decode(AppSettings.self, from: JSONSerialization.data(withJSONObject: old)).splitTunneling)
    }

    func testOppositePoliciesHaveSeparateDomainAndIPRulesAndNativeValidConfiguration() throws {
        for mode in [SplitTunnelMode.bypassSelected, .tunnelSelected] {
            var split = SplitTunnelSettings(); split.mode = mode
            split.setEntries(try SplitTunnelImport.json(Data("{\"selected.test\": [\"203.0.113.0/24\"]}".utf8)), for: mode)
            var settings = AppSettings(); settings.routingMode = .global; settings.splitTunneling = split
            for managedDNS in [false, true] {
                var profile = VPNProfile(); profile.id = "split-test"; profile.name = "Split"
                profile.kind = managedDNS ? .socks : .vless
                profile.address = "127.0.0.1"; profile.port = managedDNS ? ManagedDNSSettings.port : 9000
                profile.credential = "9f774dc1-395b-4397-890a-123456789abc"
                let json = XrayConfigurationBuilder.build(profile: profile, settings: settings)
                let baseline = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
                // Saved JSON stays a baseline; the extension reads the latest setting each time.
                XCTAssertFalse(String(decoding: try JSONSerialization.data(withJSONObject: baseline), as: UTF8.self).contains("selected.test"))
                let root = TunnelConfiguration.applying(to: baseline, settings: settings, isTURN: !managedDNS)
                let routing = try XCTUnwrap(root["routing"] as? [String: Any])
                let rules = try XCTUnwrap(routing["rules"] as? [[String: Any]])
                XCTAssertEqual(routing["domainStrategy"] as? String, "AsIs")
                XCTAssertFalse(rules.contains { $0["domain"] as? [String] == ["domain:selected.test"] })
                let ip = try XCTUnwrap(rules.first { $0["ip"] as? [String] == ["203.0.113.0/24"] })
                XCTAssertNil(ip["domain"])
                XCTAssertEqual(ip["outboundTag"] as? String, mode == .bypassSelected ? "direct" : "proxy")
                let fallback = try XCTUnwrap(rules.first { $0["network"] as? String == "tcp,udp" && $0["inboundTag"] != nil })
                XCTAssertEqual(fallback["outboundTag"] as? String, mode == .bypassSelected ? "proxy" : "direct")
                XCTAssertEqual(rules.first?["port"] as? String, "53")
                XCTAssertEqual(rules.first?["outboundTag"] as? String, "kindly-dns")
                let dns = try XCTUnwrap(root["dns"] as? [String: Any])
                let servers = try XCTUnwrap(dns["servers"] as? [[String: Any]])
                XCTAssertEqual(servers.first?["tag"] as? String, mode == .bypassSelected ? "kindly-dns-direct" : "kindly-dns-query")
                XCTAssertEqual(servers.last?["tag"] as? String, "kindly-dns-query")
                XCTAssertTrue(servers.contains { $0["tag"] as? String == "kindly-dns-direct" })
                XCTAssertEqual(dns["disableFallbackIfMatch"] as? Bool, true)
                let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".json")
                defer { try? FileManager.default.removeItem(at: file) }
                try JSONSerialization.data(withJSONObject: root).write(to: file)
                try SwiftyXray.testConfiguration(dataDir: Bundle.main.resourceURL!.path, configPath: file.path)
            }
        }
    }

    func testEmptyListsDefaultOffAndProbeIsolation() throws {
        let root: [String: Any] = ["routing": ["rules": []], "dns": ["servers": ["1.1.1.1"]]]
        XCTAssertTrue(NSDictionary(dictionary: SplitTunnelRouting.applying(to: root, settings: AppSettings())).isEqual(to: root))
        for mode in [SplitTunnelMode.bypassSelected, .tunnelSelected] {
            var settings = AppSettings(); var split = SplitTunnelSettings(); split.mode = mode; settings.splitTunneling = split
            let transformed = SplitTunnelRouting.applying(to: root, settings: settings)
            let rules = try XCTUnwrap((transformed["routing"] as? [String: Any])?["rules"] as? [[String: Any]])
            let fallback = try XCTUnwrap(rules.first { $0["network"] as? String == "tcp,udp" })
            XCTAssertEqual(fallback["inboundTag"] as? [String], ["in_proxy", "kindly-socks"])
            XCTAssertEqual(fallback["outboundTag"] as? String, mode == .bypassSelected ? "proxy" : "direct")
            let probe = try ProbeConfiguration.adding(to: transformed, port: 12345, request: XCTUnwrap(HTTPProbeRequest(HTTPProbeRequest.recoveryURL)))
            let probeRules = try XCTUnwrap((probe["routing"] as? [String: Any])?["rules"] as? [[String: Any]])
            XCTAssertEqual(probeRules.first?["inboundTag"] as? [String], ["kindly-health"])
            XCTAssertEqual(probeRules.first?["outboundTag"] as? String, "proxy")
        }
    }
}
