import XCTest
import SwiftUI
import UIKit
@testable import TnDtun

final class ApplicationBackupTests: XCTestCase {
    @MainActor func testTURNChannelsPersistAndBackupWithoutChangingOtherSettings() throws {
        try withStore { store, file, defaults in
            try store.restore(fixture())
            let originalProfiles = store.configurations
            let split = store.splitTunneling
            for count in TURNSettings.sessionChoices {
                store.turnSessionCount = count
                XCTAssertEqual(SimpleStore(fileURL: file, defaults: defaults).turnSessionCount, count)
                let backup = try ApplicationBackup.decode(store.backup().encoded())
                XCTAssertEqual(backup.effectiveTURNSessionCount, count)
                try store.restore(backup)
                XCTAssertEqual(store.turnSessionCount, count)
                XCTAssertEqual(store.configurations, originalProfiles)
                XCTAssertEqual(store.splitTunneling, split)
            }
            var legacy = try XCTUnwrap(JSONSerialization.jsonObject(with: store.backup().encoded()) as? [String: Any])
            legacy.removeValue(forKey: "turnSessionCount")
            let decoded = try ApplicationBackup.decode(JSONSerialization.data(withJSONObject: legacy))
            XCTAssertEqual(decoded.turnSessionCount, 10)
            XCTAssertEqual(decoded.effectiveTURNSessionCount, 10)
            try store.restore(decoded)
            XCTAssertEqual(store.turnSessionCount, 10)
            var invalid = try store.backup()
            invalid.turnSessionCount = 3
            XCTAssertThrowsError(try store.restore(invalid))
            XCTAssertEqual(store.configurations, originalProfiles)
            XCTAssertEqual(store.splitTunneling, split)
        }
    }

    @MainActor func testTURNChannelsReachRuntimeAndSurviveProfilePreparation() throws {
        let runtime = AppStore()
        runtime.applyAutomation(autoCaptcha: true, autoRecovery: false, turnSessionCount: 2)
        var value = SimpleConfiguration(); value.mode = .turn
        value.callLink = "https://vk.com/call/join/test"
        value.server = "203.0.113.10:56011"
        value.vlessID = "b831381d-6324-4d53-ad4f-8cda48b30811"
        try runtime.prepare(value)
        XCTAssertEqual(runtime.turnSettings.sessionCount, 2)
        runtime.restoreSelection([value], profileID: value.id)
        XCTAssertEqual(runtime.turnSettings.sessionCount, 2)
        XCTAssertEqual(try JSONDecoder().decode(AppSettings.self, from: JSONEncoder().encode(runtime.settings)).effectiveTURNSessionCount, 2)
        runtime.applyAutomation(autoCaptcha: true, autoRecovery: false)
        XCTAssertEqual(runtime.turnSettings.sessionCount, 2)
        runtime.applyAutomation(autoCaptcha: true, autoRecovery: false, turnSessionCount: 3)
        XCTAssertEqual(runtime.turnSettings.sessionCount, 10)
    }


    @MainActor func testAutoConnectPreferenceSurvivesRestartAndBackupWithoutChangingLegacyDefault() throws {
        try withStore { store, file, defaults in
            XCTAssertFalse(store.autoConnectOnLaunch)
            store.autoConnectOnLaunch = true
            XCTAssertTrue(SimpleStore(fileURL: file, defaults: defaults).autoConnectOnLaunch)
            let backup = try store.backup()
            XCTAssertEqual(backup.autoConnectOnLaunch, true)
            var legacy = try XCTUnwrap(JSONSerialization.jsonObject(with: backup.encoded()) as? [String: Any])
            legacy.removeValue(forKey: "autoConnectOnLaunch")
            let decoded = try ApplicationBackup.decode(JSONSerialization.data(withJSONObject: legacy))
            XCTAssertNil(decoded.autoConnectOnLaunch)
            try store.restore(decoded)
            XCTAssertFalse(store.autoConnectOnLaunch)
            try store.restore(backup)
            XCTAssertTrue(store.autoConnectOnLaunch)
        }
    }

    @MainActor func testBuiltInDNSCannotBeChangedDeletedOrReplacedByBackup() throws {
        try withStore { store, file, defaults in
            let original = try XCTUnwrap(store.builtInDNS)
            XCTAssertEqual(original.dns.domain, try PanelContract.bundled().dns.domain)
            XCTAssertEqual(original.dns.publicKey, try PanelContract.bundled().dns.publicKey)
            store.mode = .dns
            XCTAssertEqual(store.visibleConfigurations.first?.id, original.id)
            XCTAssertThrowsError(try store.remove(original))
            var forged = original; forged.dns.domain = "replacement.example.test"
            XCTAssertThrowsError(try store.save(forged))
            store.rememberSelection(original.id)
            let portable = try ApplicationBackup.decode(store.backup().encoded())
            XCTAssertFalse(portable.profiles.contains(where: \.isBuiltInDNS))
            XCTAssertEqual(portable.selectedProfileID, original.id)
            var incoming = try fixture(); incoming.profiles.append(forged)
            try store.restore(incoming)
            let restarted = SimpleStore(fileURL: file, defaults: defaults)
            XCTAssertEqual(restarted.builtInDNS, original)
            XCTAssertEqual(restarted.availableConfigurations.filter(\.isBuiltInDNS).count, 1)
            XCTAssertEqual(restarted.configurations.count, incoming.profiles.count - 1)
            XCTAssertEqual(try SimpleStore.manualIDs(at: file).contains(original.id), true)
        }
    }

    #if targetEnvironment(macCatalyst)
    func testMacCorruptPrimaryRestoresPreviousValidSettingsAndPreservesEvidence() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let preferences = MacSharedPreferences(directoryURL: directory)
        preferences.set("saved-profile", forKey: "profile")
        preferences.set(true, forKey: "autoCaptcha")
        preferences.set(12, forKey: "counter")
        let primary = directory.appendingPathComponent("shared-preferences.plist")
        let broken = Data("bplist00truncated-binary-plist".utf8)
        try broken.write(to: primary, options: .atomic)
        let restarted = MacSharedPreferences(directoryURL: directory)
        XCTAssertEqual(restarted.string(forKey: "profile"), "saved-profile")
        XCTAssertTrue(restarted.bool(forKey: "autoCaptcha"))
        XCTAssertNoThrow(try restarted.verifyAccess())
        restarted.set("updated-profile", forKey: "profile")
        XCTAssertTrue(restarted.synchronize())
        XCTAssertEqual(MacSharedPreferences(directoryURL: directory).string(forKey: "profile"), "updated-profile")
        let saved = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
            .filter { $0.lastPathComponent.hasPrefix("shared-preferences.corrupt-") }
        XCTAssertEqual(saved.count, 1)
        XCTAssertEqual(try Data(contentsOf: XCTUnwrap(saved.first)), broken)
    }

    func testMacCorruptPreferencesWithoutBackupAllowNewConnectionSettings() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try Data("bplist00broken".utf8).write(to: directory.appendingPathComponent("shared-preferences.plist"))
        let preferences = MacSharedPreferences(directoryURL: directory)
        XCTAssertNoThrow(try preferences.verifyAccess())
        preferences.set(Data("new-config".utf8), forKey: "active-config")
        XCTAssertTrue(preferences.synchronize())
        XCTAssertEqual(MacSharedPreferences(directoryURL: directory).data(forKey: "active-config"), Data("new-config".utf8))
    }

    func testMacConcurrentAppAndProviderWritesDoNotLoseKeys() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        DispatchQueue.concurrentPerform(iterations: 24) { index in
            MacSharedPreferences(directoryURL: directory).set("value-\(index)", forKey: "key-\(index)")
        }
        let reader = MacSharedPreferences(directoryURL: directory)
        for index in 0..<24 { XCTAssertEqual(reader.string(forKey: "key-\(index)"), "value-\(index)") }
        let blocked = directory.appendingPathComponent("file-instead-of-directory")
        let original = Data("keep".utf8); try original.write(to: blocked)
        XCTAssertThrowsError(try MacSharedPreferences(directoryURL: blocked).verifyAccess())
        XCTAssertEqual(try Data(contentsOf: blocked), original)
    }
    #endif

    @MainActor func testDNSEditorAndSettingsRenderWithExplicitDependencies() throws {
        try withStore { store, _, _ in
            let backup = try fixture()
            try store.restore(backup)
            let editor = ConfigurationEditor(store: store, configuration: backup.profiles[1]) { _ in }
            let host = UIHostingController(rootView: editor)
            host.view.frame = CGRect(x: 0, y: 0, width: 600, height: 800)
            host.view.layoutIfNeeded()
            XCTAssertGreaterThan(host.sizeThatFits(in: host.view.frame.size).height, 0)
            let runtime = AppStore()
            let settings = SettingsEditor(store: store, runtime: runtime,
                autoCaptcha: true, autoRecovery: true, autoConnectOnLaunch: false, turnCheckInterval: 30, turnSessionCount: 10, splitTunneling: backup.splitTunneling,
                amneziaSplitEnabled: false, fullTunnelMinutes: 15,
                onImport: { _ in }, onSave: { _, _, _, _, _, _, _, _ in })
            let settingsHost = UIHostingController(rootView: settings)
            settingsHost.view.frame = host.view.frame
            settingsHost.view.layoutIfNeeded()
            XCTAssertGreaterThan(settingsHost.sizeThatFits(in: host.view.frame.size).height, 0)
        }
    }

    @MainActor func testSharedContainerAndPreferencesAreWritableBySignedHost() throws {
        guard let directory = AppGroup.containerURL else { return XCTFail("Shared VPN container unavailable") }
        try AppGroup.verifyAccess()
        let key = "shared-access-test-" + UUID().uuidString
        let file = directory.appendingPathComponent(key)
        defer { AppGroup.defaults.removeObject(forKey: key); try? FileManager.default.removeItem(at: file) }
        try Data("shared".utf8).write(to: file, options: .atomic)
        AppGroup.defaults.set(key, forKey: key)
        #if targetEnvironment(macCatalyst)
        XCTAssertTrue(AppGroup.defaults.synchronize())
        XCTAssertEqual(MacSharedPreferences().string(forKey: key), key)
        #else
        XCTAssertEqual(UserDefaults(suiteName: AppGroup.id)?.string(forKey: key), key)
        #endif
        XCTAssertEqual(try Data(contentsOf: file), Data("shared".utf8))
    }

    func testSharedStorageProbeCleansUpAndReportsActualFileErrors() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try AppGroup.verifyFileAccess(in: directory)
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: directory.path).isEmpty)
        let blocked = directory.appendingPathComponent("not-a-directory")
        try Data("original".utf8).write(to: blocked)
        XCTAssertThrowsError(try AppGroup.verifyFileAccess(in: blocked)) { error in
            XCTAssertEqual((error as NSError).domain, "TnDtun.Storage")
            XCTAssertNotNil((error as NSError).userInfo[NSUnderlyingErrorKey])
        }
        XCTAssertEqual(try Data(contentsOf: blocked), Data("original".utf8))
    }

    @MainActor func testDNSAndTURNConnectionDataAreReadableFromSharedFiles() throws {
        let directory = try XCTUnwrap(AppGroup.containerURL)
        let active = directory.appendingPathComponent("active-xray.json")
        let dns = directory.appendingPathComponent("managed-dns.json")
        let previousActive = try? Data(contentsOf: active)
        let previousDNS = try? Data(contentsOf: dns)
        let keys = [AppGroup.activeProfileKey, AppGroup.activeConfigKey,
                    AppGroup.settingsKey, AppGroup.turnSettingsKey, "simple.turn.wrapKey"]
        let preferences = keys.map { AppGroup.defaults.object(forKey: $0) }
        defer {
            for (index, key) in keys.enumerated() {
                if let value = preferences[index] { AppGroup.defaults.set(value, forKey: key) }
                else { AppGroup.defaults.removeObject(forKey: key) }
            }
            for (url, data) in [(active, previousActive), (dns, previousDNS)] {
                if let data { try? data.write(to: url, options: .atomic) }
                else { try? FileManager.default.removeItem(at: url) }
            }
        }
        let profiles = try fixture().profiles
        let runtime = AppStore()
        for profile in profiles {
            try AppGroup.verifyAccess()
            try runtime.prepare(profile)
            XCTAssertTrue(runtime.writeActiveConfiguration())
            let configuration = try Data(contentsOf: active)
            XCTAssertNoThrow(try JSONSerialization.jsonObject(with: configuration))
            if profile.mode == .dns {
                XCTAssertEqual(try ManagedDNSStore.load(), profile.dns)
            }
        }
    }

    @MainActor func testExportDocumentContainsAllSettingsAndProfiles() async throws {
        let backup = try fixture()
        let document = try await BackupExportDocument.prepare(backup)
        XCTAssertEqual(try ApplicationBackup.decode(document.data), backup)
        var invalid = backup; invalid.schemaVersion = 999
        do {
            _ = try await BackupExportDocument.prepare(invalid)
            XCTFail("Invalid backups must never reach the save dialog")
        } catch { XCTAssertTrue(error is ConfigurationError) }
    }

    private func fixture() throws -> ApplicationBackup {
        var turn = SimpleConfiguration()
        turn.id = "turn-profile"; turn.callLink = "https://vk.ru/call/join/backup-test"
        turn.server = "203.0.113.7:56010"; turn.vlessID = "810d5f7e-7a00-4a0c-95cd-7ac733a77816"
        turn.wrapKey = String(repeating: "ac", count: 32)
        var dns = SimpleConfiguration(); dns.id = "dns-profile"; dns.mode = .dns
        dns.dns.domain = "tunnel.example.com"; dns.dns.publicKey = String(repeating: "bd", count: 32)
        dns.dns.resolver = "203.0.113.53:53"; dns.dns.savedResolvers = ["203.0.113.53:53", "1.1.1.1:53"]
        dns.dns.autoDetectResolver = false
        dns.dns.useWiFiResolver = true; dns.dns.wifiResolver = "8.8.8.8:53"; dns.dns.sessionCount = 8
        dns.dns.tunnelType = "ssh"; dns.dns.sshUsername = "tester"
        dns.dns.sshPassword = "  password with spaces  "
        dns.dns.sshPrivateKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n-----END OPENSSH PRIVATE KEY-----\n"
        dns.dns.sshHostKey = "SHA256:fixture-public-host-fingerprint"
        var split = SplitTunnelSettings(); split.mode = .tunnelSelected
        split.bypassEntries = [SplitTunnelEntry(address: "direct.example.com", networks: ["203.0.113.0/24"])]
        split.tunnelEntries = [SplitTunnelEntry(address: "tunnel.example.com"),
                               SplitTunnelEntry(address: "copilot", networks: ["198.51.100.0/24"], isNetworkGroup: true)]
        return try ApplicationBackup(appBuild: "7", profiles: [turn, dns], mode: .dns,
                                     autoCaptcha: false, autoRecovery: false,
                                     savedDNSServers: ["203.0.113.53:53", "[2001:db8::53]:5353"],
                                     splitTunneling: split, selectedProfileID: dns.id, turnCheckInterval: 120).validated()
    }

    @MainActor private func withStore(_ body: (SimpleStore, URL, UserDefaults) throws -> Void) throws {
        let name = "backup-tests-" + UUID().uuidString
        let defaults = UserDefaults(suiteName: name)!
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(name)
        let file = directory.appendingPathComponent("profiles.json")
        defer { defaults.removePersistentDomain(forName: name); try? FileManager.default.removeItem(at: directory) }
        try body(SimpleStore(fileURL: file, defaults: defaults), file, defaults)
    }

    func testJSONRoundTripIncludesAllCredentialsAndNetworkOptions() throws {
        let backup = try fixture()
        let decoded = try ApplicationBackup.decode(backup.encoded())
        XCTAssertEqual(decoded, backup)
        XCTAssertEqual(decoded.profiles[1].dns.sshPassword, "  password with spaces  ")
        XCTAssertEqual(decoded.profiles[1].dns.sshPrivateKey, backup.profiles[1].dns.sshPrivateKey)
        XCTAssertTrue(decoded.profiles[1].dns.useWiFiResolver)
        XCTAssertFalse(decoded.profiles[1].dns.autoDetectResolver)
        XCTAssertEqual(decoded.profiles[1].dns.sessionCount, 8)
        XCTAssertEqual(decoded.turnCheckInterval, 120)
    }

    @MainActor func testOldBackupRestoresDefaultTURNIntervalAndDraftExportIncludesNewInterval() throws {
        var old = try XCTUnwrap(JSONSerialization.jsonObject(with: fixture().encoded()) as? [String: Any])
        old.removeValue(forKey: "turnCheckInterval")
        let migrated = try ApplicationBackup.decode(JSONSerialization.data(withJSONObject: old))
        XCTAssertEqual(migrated.effectiveTURNCheckInterval, 30)
        try withStore { store, file, defaults in
            store.turnCheckInterval = 300
            try store.restore(migrated)
            XCTAssertEqual(store.turnCheckInterval, 30)
            XCTAssertEqual(SimpleStore(fileURL: file, defaults: defaults).turnCheckInterval, 30)
            let draft = try ApplicationBackup.decode(store.backup(turnCheckInterval: 60).encoded())
            XCTAssertEqual(draft.turnCheckInterval, 60)
            XCTAssertEqual(store.turnCheckInterval, 30)
        }
    }

    @MainActor func testFullRestoreReplacesExistingDataAndSurvivesRestart() throws {
        try withStore { store, file, defaults in
            var old = try fixture().profiles[0]; old.id = "old"; old.server = "198.51.100.8:443"
            try store.save(old); store.rememberSelection(old.id)
            try store.rememberDNSServers(["9.9.9.9"])
            let incoming = try ApplicationBackup.decode(fixture().encoded())
            try store.restore(incoming)
            for destination in [store, SimpleStore(fileURL: file, defaults: defaults)] {
                var copy = try destination.backup()
                copy.appVersion = incoming.appVersion; copy.appBuild = incoming.appBuild; copy.createdAt = incoming.createdAt
                XCTAssertEqual(copy, incoming)
                XCTAssertFalse(destination.configurations.contains { $0.id == old.id })
            }
            XCTAssertFalse(FileManager.default.fileExists(atPath: file.appendingPathExtension("restore.json").path))
        }
    }

    @MainActor func testExportFromOneStoreRestoresIdenticallyInAnother() throws {
        try withStore { source, _, _ in
            try source.restore(fixture())
            let exported = try source.backup().encoded()
            try withStore { destination, file, defaults in
                try destination.restore(ApplicationBackup.decode(exported))
                let restarted = SimpleStore(fileURL: file, defaults: defaults)
                XCTAssertEqual(restarted.configurations, source.configurations)
                XCTAssertEqual(restarted.splitTunneling, source.splitTunneling)
                XCTAssertEqual(restarted.savedDNSServers, source.savedDNSServers)
                XCTAssertEqual(restarted.mode, source.mode)
                XCTAssertEqual(restarted.autoCaptcha, source.autoCaptcha)
                XCTAssertEqual(restarted.autoRecovery, source.autoRecovery)
                XCTAssertEqual(restarted.turnCheckInterval, source.turnCheckInterval)
                XCTAssertEqual(restarted.selectedProfileID, source.selectedProfileID)
            }
        }
    }

    @MainActor func testInvalidBackupNeverChangesExistingData() throws {
        try withStore { store, file, defaults in
            try store.restore(fixture())
            let originalProfiles = try Data(contentsOf: file)
            let originalDefaults = defaults.dictionaryRepresentation() as NSDictionary
            var invalid = try fixture(); invalid.profiles.append(invalid.profiles[0])
            XCTAssertThrowsError(try store.restore(invalid))
            invalid = try fixture(); invalid.savedDNSServers = ["not-an-ip"]
            XCTAssertThrowsError(try store.restore(invalid))
            invalid = try fixture(); invalid.profiles[1].dns.publicKey = "broken-key"
            XCTAssertThrowsError(try store.restore(invalid))
            invalid = try fixture(); invalid.selectedProfileID = "missing"
            XCTAssertThrowsError(try store.restore(invalid))
            for interval in [0, 14, 301, Int.max] {
                invalid = try fixture(); invalid.turnCheckInterval = interval
                XCTAssertThrowsError(try store.restore(invalid))
            }
            XCTAssertEqual(try Data(contentsOf: file), originalProfiles)
            XCTAssertEqual(defaults.dictionaryRepresentation() as NSDictionary, originalDefaults)
            XCTAssertEqual(store.configurations, try fixture().profiles)
        }
    }

    func testMalformedPartialAndFutureFormatsAreRejected() throws {
        XCTAssertThrowsError(try ApplicationBackup.decode(Data("{}".utf8)))
        XCTAssertThrowsError(try ApplicationBackup.decode(Data("not json".utf8)))
        var root = try XCTUnwrap(JSONSerialization.jsonObject(with: fixture().encoded()) as? [String: Any])
        root.removeValue(forKey: "splitTunneling")
        XCTAssertThrowsError(try ApplicationBackup.decode(JSONSerialization.data(withJSONObject: root)))
        root["schemaVersion"] = 99
        XCTAssertThrowsError(try ApplicationBackup.decode(JSONSerialization.data(withJSONObject: root)))
        XCTAssertThrowsError(try ApplicationBackup.decode(Data(repeating: 32, count: ApplicationBackup.maximumSize + 1)))
    }

    @MainActor func testFailedFileWriteDoesNotChangeSettingsOrLeaveJournal() throws {
        try withStore { store, file, defaults in
            try FileManager.default.createDirectory(at: file, withIntermediateDirectories: true)
            let before = defaults.dictionaryRepresentation() as NSDictionary
            XCTAssertThrowsError(try store.restore(fixture()))
            XCTAssertTrue(store.configurations.isEmpty)
            XCTAssertEqual(defaults.dictionaryRepresentation() as NSDictionary, before)
            XCTAssertFalse(FileManager.default.fileExists(atPath: file.appendingPathExtension("restore.json").path))
        }
    }

    @MainActor func testConfirmedImportJournalReplaysAfterInterruptedWrite() throws {
        try withStore { _, file, defaults in
            try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data("corrupt previous profiles".utf8).write(to: file)
            let incoming = try fixture()
            try incoming.encoded().write(to: file.appendingPathExtension("restore.json"))
            let restored = SimpleStore(fileURL: file, defaults: defaults)
            XCTAssertEqual(restored.configurations, incoming.profiles)
            XCTAssertEqual(restored.splitTunneling, incoming.splitTunneling)
            XCTAssertEqual(restored.savedDNSServers, incoming.savedDNSServers)
            XCTAssertEqual(restored.selectedProfileID, incoming.selectedProfileID)
            XCTAssertNil(restored.error)
            XCTAssertFalse(FileManager.default.fileExists(atPath: file.appendingPathExtension("restore.json").path))
        }
    }

    @MainActor func testLegacyProfilesAndSelectionEditingDeletion() throws {
        try withStore { store, file, defaults in
            var profile = try fixture().profiles[0]; profile.vlessID = ""
            try store.save(profile)
            store.rememberSelection(profile.id)
            profile.server = "203.0.113.8:443"; try store.save(profile)
            XCTAssertEqual(store.selectedProfileID, profile.id)
            let legacy = SimpleStore(fileURL: file, defaults: defaults)
            XCTAssertEqual(legacy.configurations, [profile])
            XCTAssertEqual(try ApplicationBackup.decode(legacy.backup().encoded()).profiles, [profile])
            try legacy.remove(profile)
            XCTAssertNil(legacy.selectedProfileID)
        }
    }

    @MainActor func testEmptyBackupExplicitlyClearsAllProfilesAndLists() throws {
        try withStore { store, _, _ in
            try store.restore(fixture())
            let empty = ApplicationBackup(profiles: [], mode: .turn, autoCaptcha: true, autoRecovery: true,
                                          savedDNSServers: [], splitTunneling: SplitTunnelSettings())
            try store.restore(empty)
            XCTAssertTrue(store.configurations.isEmpty)
            XCTAssertTrue(store.savedDNSServers.isEmpty)
            XCTAssertNil(store.selectedProfileID)
            XCTAssertEqual(store.splitTunneling, SplitTunnelSettings())
        }
    }
}
