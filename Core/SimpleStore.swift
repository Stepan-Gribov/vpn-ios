import Foundation
import SwiftUI

@MainActor
final class SimpleStore: ObservableObject {
    @Published private(set) var configurations: [SimpleConfiguration] = []
    @Published var mode: TunnelMode = .turn { didSet { defaults.set(mode.rawValue, forKey: "simple.mode") } }
    @Published var error: String?
    @Published var autoCaptcha = false { didSet { defaults.set(autoCaptcha, forKey: "simple.autoCaptcha") } }
    @Published var autoConnectOnLaunch = false { didSet { defaults.set(autoConnectOnLaunch, forKey: "simple.autoConnectOnLaunch") } }
    @Published var autoRecovery = true { didSet { defaults.set(autoRecovery, forKey: "simple.autoRecovery") } }
    @Published var amneziaSplitEnabled = false { didSet { defaults.set(amneziaSplitEnabled, forKey: "simple.amneziaSplitEnabled") } }
    @Published var fullTunnelMinutes = TemporaryFullTunnelPolicy.defaultMinutes { didSet { defaults.set(fullTunnelMinutes, forKey: "simple.fullTunnelMinutes") } }
    @Published var turnCheckInterval = TURNHealthCheckPolicy.defaultInterval {
        didSet { defaults.set(turnCheckInterval, forKey: "simple.turnCheckInterval") }
    }
    @Published var turnSessionCount = TURNSettings.defaultSessions {
        didSet { defaults.set(turnSessionCount, forKey: "simple.turnSessionCount") }
    }
    @Published private(set) var savedDNSServers: [String] = []
    @Published private(set) var splitTunneling = SplitTunnelSettings()
    @Published private(set) var selectedProfileID: String?
    private let defaults: UserDefaults
    private let fileURL: URL
    private var loadFailed = false
    let panelVault: PanelVault
    private(set) var builtInDNS: SimpleConfiguration?
    var availableConfigurations: [SimpleConfiguration] { (builtInDNS.map { [$0] } ?? []) + configurations }
    @Published private(set) var applicationDNSServers: [String] = []
    @Published private(set) var applicationDNSTunnel: PanelDNS?
    var manualProfileIDs: Set<String> { Set(configurations.filter { $0.managed == nil }.map(\.id)).union([SimpleConfiguration.builtInDNSID]) }
    var manualFileURL: URL { fileURL }
    nonisolated static func manualIDs(at url: URL) throws -> Set<String> {
        guard FileManager.default.fileExists(atPath: url.path) else { return [SimpleConfiguration.builtInDNSID] }
        return Set(try JSONDecoder().decode([SimpleConfiguration].self, from: Data(contentsOf: url)).filter { $0.managed == nil && !$0.isBuiltInDNS }.map(\.id)).union([SimpleConfiguration.builtInDNSID])
    }
    var panelBaseline: PanelSettings {
        PanelSettings(autoCaptcha: autoCaptcha, autoRecovery: autoRecovery, turnCheckInterval: turnCheckInterval,
                      dnsServers: applicationDNSServers,
                      dnsTunnel: applicationDNSTunnel, splitTunneling: splitTunneling)
    }
    func reloadPanelProjection() throws {
        let state = try panelVault.snapshot()
        let assigned = try state.subscriptions.flatMap { sub in
            try sub.package.profiles.map { try $0.configuration(subscriptionID: sub.id, expiresAt: sub.package.expiresAt) }
        }
        configurations = configurations.filter { $0.managed == nil && !$0.isBuiltInDNS } + assigned
        if let selectedProfileID, !availableConfigurations.contains(where: { $0.id == selectedProfileID }) { rememberSelection(nil) }
        if let settings = state.globalSettings, defaults.string(forKey: "simple.panel.settingsEpoch") != state.settingsEpoch {
            autoCaptcha = false; autoRecovery = settings.autoRecovery
            turnCheckInterval = settings.turnCheckInterval
            try saveSplitTunneling(settings.splitTunneling)
            applicationDNSServers = settings.dnsServers; applicationDNSTunnel = settings.dnsTunnel
            defaults.set(settings.dnsServers, forKey: "simple.applicationDNSServers")
            defaults.set(try JSONEncoder().encode(settings.dnsTunnel), forKey: "simple.applicationDNSTunnel")
            defaults.set(state.settingsEpoch, forKey: "simple.panel.settingsEpoch")
        }
    }

    init(fileURL: URL? = nil, defaults: UserDefaults = .standard, panelVault: PanelVault? = nil) {
        self.defaults = defaults
        self.panelVault = panelVault ?? (fileURL == nil ? .shared : PanelVault(directory: fileURL!.deletingLastPathComponent().appendingPathComponent("test-panel"), key: Data(repeating: 42, count: 32)))
        let directory = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        self.fileURL = fileURL ?? directory.appendingPathComponent("simple-configurations.json")
        do { builtInDNS = try SimpleConfiguration.builtInDNS() }
        catch { self.error = "The built-in DNS configuration is unavailable. Reinstall TnDtun." }
        mode = TunnelMode(rawValue: defaults.string(forKey: "simple.mode") ?? "turn") ?? .turn
        autoCaptcha = false
        autoConnectOnLaunch = defaults.bool(forKey: "simple.autoConnectOnLaunch")
        autoRecovery = defaults.object(forKey: "simple.autoRecovery") as? Bool ?? true
        amneziaSplitEnabled = defaults.bool(forKey: "simple.amneziaSplitEnabled")
        let minutes = defaults.object(forKey: "simple.fullTunnelMinutes") as? Int
        fullTunnelMinutes = minutes.flatMap { TemporaryFullTunnelPolicy.minutes.contains($0) ? $0 : nil } ?? TemporaryFullTunnelPolicy.defaultMinutes
        turnCheckInterval = TURNHealthCheckPolicy.interval(defaults.object(forKey: "simple.turnCheckInterval") as? Int)
        turnSessionCount = TURNSettings.normalizedSessions(defaults.object(forKey: "simple.turnSessionCount") as? Int)
        savedDNSServers = defaults.stringArray(forKey: "simple.savedDNSServers") ?? []
        selectedProfileID = defaults.string(forKey: "simple.selectedProfileID")
        applicationDNSServers = defaults.stringArray(forKey: "simple.applicationDNSServers") ?? []
        if let data = defaults.data(forKey: "simple.applicationDNSTunnel") { applicationDNSTunnel = try? JSONDecoder().decode(PanelDNS.self, from: data) }
        if let data = defaults.data(forKey: "simple.splitTunneling") {
            do { splitTunneling = try JSONDecoder().decode(SplitTunnelSettings.self, from: data).validated() }
            catch { self.error = "The split tunneling list could not be read. The saved data is retained on this device." }
        }
        do {
            if FileManager.default.fileExists(atPath: self.fileURL.path) {
                configurations = try JSONDecoder().decode([SimpleConfiguration].self, from: Data(contentsOf: self.fileURL)).filter { !$0.isBuiltInDNS }
            }
        } catch { self.loadFailed = true; self.error = "Saved configurations could not be read. The data is retained on this device." }
        // Complete a previously confirmed import if iOS terminated the app
        // between the atomic profile write and the UserDefaults update.
        if FileManager.default.fileExists(atPath: restoreJournalURL.path) {
            do {
                let pending = try ApplicationBackup.decode(Data(contentsOf: restoreJournalURL))
                try restore(pending, recovering: true)
            } catch { self.error = "Settings import could not be completed. The backup is retained so you can try again." }
        }
        do { try reloadPanelProjection() }
        catch { self.error = error.localizedDescription }
    }

    var visibleConfigurations: [SimpleConfiguration] { availableConfigurations.filter { $0.mode == mode } }

    func save(_ configuration: SimpleConfiguration) throws {
        guard !configuration.isBuiltInDNS else { throw ConfigurationError("The built-in DNS profile cannot be changed. Add another DNS profile instead.") }
        guard configuration.managed == nil, !configurations.contains(where: { $0.id == configuration.id && $0.managed != nil }) else {
            throw PanelFailure("Subscription profiles are managed by your administrator. Use Subscription to update them.")
        }
        let value = try configuration.validated()
        var updated = configurations
        if let index = updated.firstIndex(where: { $0.id == value.id }) { updated[index] = value }
        else { updated.append(value) }
        try persist(updated)
        configurations = updated
    }

    func remove(_ configuration: SimpleConfiguration) throws {
        guard !configuration.isBuiltInDNS else { throw ConfigurationError("The built-in DNS profile is always available and cannot be deleted.") }
        guard configuration.managed == nil else { throw PanelFailure("Remove this subscription from Subscription settings instead.") }
        let updated = configurations.filter { $0.id != configuration.id }
        try persist(updated)
        configurations = updated
        if selectedProfileID == configuration.id { rememberSelection(nil) }
    }

    func rememberDNSServers(_ addresses: [String]) throws {
        let normalized = try addresses.map(ManagedDNSSettings.normalizeResolver)
        var updated = [String]()
        for raw in savedDNSServers {
            if let address = try? ManagedDNSSettings.normalizeResolver(raw), !updated.contains(address) {
                updated.append(address)
            }
        }
        for address in normalized where !updated.contains(address) { updated.append(address) }
        savedDNSServers = updated
        defaults.set(updated, forKey: "simple.savedDNSServers")
    }

    /// Apply a fresh physical-network resolver to the selected profile, retaining
    /// the explicit Wi-Fi override and the saved resolver when detection fails.
    func applyingDetectedDNS(to configuration: SimpleConfiguration, servers: [String], usingWiFi: Bool?) throws -> SimpleConfiguration {
        guard configuration.mode == .dns, configuration.dns.autoDetectResolver else { return configuration }
        // With an unknown interface, keep an explicit override rather than
        // replacing the carrier DNS with a potentially unrelated Wi-Fi DNS.
        guard !(configuration.dns.useWiFiResolver && usingWiFi != false) else { return configuration }
        let addresses = servers.compactMap { try? ManagedDNSSettings.normalizeResolver($0) }
            .reduce(into: [String]()) { list, address in
                if !list.contains(address) { list.append(address) }
            }
        guard let first = addresses.first else { return configuration }
        var updated = configuration
        updated.dns.resolver = first
        updated.dns.savedResolvers += addresses
        updated = try updated.validated(forConnection: true)
        do { if !updated.isBuiltInDNS { try save(updated) } }
        catch {
            // DNS discovery is a connection input, not a user-requested edit.
            // Keep the on-disk profile intact and use the new DNS for this run.
            RuntimeLog.write("Detected DNS will be used for this connection; profile update could not be saved: \(error.localizedDescription)")
        }
        try rememberDNSServers(addresses)
        return updated
    }

    func forgetDNSServer(_ address: String) {
        savedDNSServers.removeAll { $0 == address }
        defaults.set(savedDNSServers, forKey: "simple.savedDNSServers")
    }

    func saveSplitTunneling(_ value: SplitTunnelSettings) throws {
        let validated = try value.validated()
        let data = try JSONEncoder().encode(validated)
        defaults.set(data, forKey: "simple.splitTunneling")
        splitTunneling = validated
    }

    func rememberSelection(_ profileID: String?) {
        selectedProfileID = profileID.flatMap { id in availableConfigurations.contains(where: { $0.id == id }) ? id : nil }
        defaults.set(selectedProfileID, forKey: "simple.selectedProfileID")
    }

    func backup(autoCaptcha: Bool? = nil, autoRecovery: Bool? = nil, turnCheckInterval: Int? = nil, autoConnectOnLaunch: Bool? = nil,
                splitTunneling: SplitTunnelSettings? = nil, selectedProfileID: String? = nil,
                amneziaSplitEnabled: Bool? = nil, fullTunnelMinutes: Int? = nil, turnSessionCount: Int? = nil) throws -> ApplicationBackup {
        try backupSnapshot(autoCaptcha: autoCaptcha, autoRecovery: autoRecovery,
                           turnCheckInterval: turnCheckInterval, autoConnectOnLaunch: autoConnectOnLaunch,
                           splitTunneling: splitTunneling, selectedProfileID: selectedProfileID,
                           amneziaSplitEnabled: amneziaSplitEnabled, fullTunnelMinutes: fullTunnelMinutes, turnSessionCount: turnSessionCount).validated()
    }

    // Capture UI-owned values cheaply; validate and encode the snapshot off the UI thread.
    func backupSnapshot(autoCaptcha: Bool? = nil, autoRecovery: Bool? = nil, turnCheckInterval: Int? = nil, autoConnectOnLaunch: Bool? = nil,
                        splitTunneling: SplitTunnelSettings? = nil, selectedProfileID: String? = nil,
                        amneziaSplitEnabled: Bool? = nil, fullTunnelMinutes: Int? = nil, turnSessionCount: Int? = nil) throws -> ApplicationBackup {
        guard !loadFailed else { throw ConfigurationError("Profiles could not be read. Export was stopped to avoid creating an incomplete backup.") }
        let selected = selectedProfileID ?? self.selectedProfileID
        return ApplicationBackup(appVersion: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "1.0",
                                 appBuild: Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "",
                                 profiles: configurations.map { var value = $0; value.managed = nil; return value }, mode: mode, autoCaptcha: autoCaptcha ?? self.autoCaptcha,
                                 autoRecovery: autoRecovery ?? self.autoRecovery, savedDNSServers: savedDNSServers,
                                 splitTunneling: splitTunneling ?? self.splitTunneling,
                                 selectedProfileID: selected.flatMap { id in availableConfigurations.contains(where: { $0.id == id }) ? id : nil },
                                 turnCheckInterval: turnCheckInterval ?? self.turnCheckInterval, applicationDNSServers: applicationDNSServers.isEmpty ? nil : applicationDNSServers, applicationDNSTunnel: applicationDNSTunnel, autoConnectOnLaunch: (autoConnectOnLaunch ?? self.autoConnectOnLaunch) ? true : nil,
                                 amneziaSplitEnabled: (amneziaSplitEnabled ?? self.amneziaSplitEnabled) ? true : nil,
                                 fullTunnelMinutes: (fullTunnelMinutes ?? self.fullTunnelMinutes) == TemporaryFullTunnelPolicy.defaultMinutes ? nil : (fullTunnelMinutes ?? self.fullTunnelMinutes),
                                 turnSessionCount: TURNSettings.normalizedSessions(turnSessionCount ?? self.turnSessionCount))
    }

    private var restoreJournalURL: URL { fileURL.appendingPathExtension("restore.json") }

    func restore(_ backup: ApplicationBackup, recovering: Bool = false) throws {
        var value = try backup.validated()
        let managedIDs = Set(try panelVault.snapshot().records.map(\.id))
        value.profiles = value.profiles.map { profile in
            var item = profile; item.managed = nil
            if managedIDs.contains(item.id) {
                item.id = UUID().uuidString
                if value.selectedProfileID == profile.id { value.selectedProfileID = item.id }
            }
            return item
        }
        // Encode and validate everything before touching current data.
        let backupData = try value.encoded()
        let profileData = try JSONEncoder().encode(value.profiles)
        let splitData = try JSONEncoder().encode(value.splitTunneling)
        try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try backupData.write(to: restoreJournalURL, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        var journal = restoreJournalURL
        var resources = URLResourceValues(); resources.isExcludedFromBackup = true
        try? journal.setResourceValues(resources)
        do { try panelVault.withManualWrite { state in
            guard Set(value.profiles.map(\.id)).isDisjoint(with: state.records.map(\.id)) else { throw PanelFailure("Subscription profiles changed during import. Try again.") }
            try profileData.write(to: fileURL, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        } }
        catch {
            if !recovering { try? FileManager.default.removeItem(at: restoreJournalURL) }
            throw error
        }
        defaults.set(splitData, forKey: "simple.splitTunneling")
        defaults.set(value.savedDNSServers, forKey: "simple.savedDNSServers")
        configurations = value.profiles
        applicationDNSServers = value.applicationDNSServers ?? []
        applicationDNSTunnel = value.applicationDNSTunnel
        defaults.set(applicationDNSServers, forKey: "simple.applicationDNSServers")
        defaults.set(try JSONEncoder().encode(applicationDNSTunnel), forKey: "simple.applicationDNSTunnel")
        splitTunneling = value.splitTunneling
        savedDNSServers = value.savedDNSServers
        mode = value.mode; autoCaptcha = false; autoRecovery = value.autoRecovery
        autoConnectOnLaunch = value.autoConnectOnLaunch ?? false
        amneziaSplitEnabled = value.amneziaSplitEnabled ?? false
        fullTunnelMinutes = value.fullTunnelMinutes ?? TemporaryFullTunnelPolicy.defaultMinutes
        turnCheckInterval = value.effectiveTURNCheckInterval
        turnSessionCount = value.effectiveTURNSessionCount
        rememberSelection(value.selectedProfileID)
        loadFailed = false; error = nil
        try reloadPanelProjection()
        var profilesURL = fileURL; try? profilesURL.setResourceValues(resources)
        if defaults.synchronize() { try? FileManager.default.removeItem(at: restoreJournalURL) }
    }

    private func persist(_ values: [SimpleConfiguration]) throws {
        guard !loadFailed else { throw ConfigurationError("The saved file is damaged. New data was not written so the original can be recovered.") }
        try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        let manual = values.filter { $0.managed == nil && !$0.isBuiltInDNS }
        let data = try JSONEncoder().encode(manual)
        try panelVault.withManualWrite { state in
            guard Set(manual.map(\.id)).isDisjoint(with: state.records.map(\.id)) else { throw PanelFailure("This profile ID is managed by a subscription.") }
            try data.write(to: fileURL, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        }
        var url = fileURL
        var resources = URLResourceValues(); resources.isExcludedFromBackup = true
        // Excluding a successfully written file from device backups is best
        // effort and must not turn a valid profile save into a connection error.
        try? url.setResourceValues(resources)
    }
}

/// Small adapter for the unchanged KindlyVPN packet-tunnel lifecycle.
/// Panel refresh is explicit and does not participate in this lifecycle.
@MainActor
final class AppStore: ObservableObject {
    var profiles: [VPNProfile] = []
    var settings: AppSettings = {
        var value = AppSettings()
        value.routingMode = .global
        value.connectOnDemand = false
        return value
    }()
    var turnSettings = TURNSettings()
    var activeProfileId: String?
    var activeProfile: VPNProfile? { profiles.first { $0.id == activeProfileId } }

    func applyPanelDNS(_ servers: [String]) {
        guard !servers.isEmpty else {
            settings.vpnDNS = AppSettings().vpnDNS
            settings.remoteDNS = AppSettings().remoteDNS
            save(); return
        }
        settings.vpnDNS = servers.compactMap { endpoint in
            if endpoint.hasPrefix("["), let end = endpoint.firstIndex(of: "]") { return String(endpoint[endpoint.index(after: endpoint.startIndex)..<end]) }
            return endpoint.split(separator: ":").first.map(String.init)
        }
        settings.remoteDNS = "tcp://" + servers[0]
        save()
    }

    func applySplitTunneling(_ value: SplitTunnelSettings) {
        settings.splitTunneling = value
        save()
    }

    func applySplitOptions(amnezia: Bool, minutes: Int) {
        settings.amneziaSplitEnabled = amnezia
        settings.fullTunnelMinutes = TemporaryFullTunnelPolicy.minutes.contains(minutes) ? minutes : TemporaryFullTunnelPolicy.defaultMinutes
        save()
    }

    func clearPreparedConfiguration() throws {
        // Called only after the VPN is stopped, before replacing user data.
        if let url = AppGroup.activeConfigURL, FileManager.default.fileExists(atPath: url.path) {
            try FileManager.default.removeItem(at: url)
        }
        try ManagedDNSStore.clear()
        for key in [AppGroup.activeConfigKey, AppGroup.turnStatusKey, AppGroup.recoveryStatusKey,
                    AppGroup.recoveryActionKey, "simple.turn.wrapKey"] { AppGroup.defaults.removeObject(forKey: key) }
        profiles = []; activeProfileId = nil; turnSettings = TURNSettings()
        RecoveryTransportStore.enabled = false
        save()
    }

    func applyAutomation(autoCaptcha: Bool, autoRecovery: Bool, turnCheckInterval: Int = TURNHealthCheckPolicy.defaultInterval, turnSessionCount: Int? = nil) {
        turnSettings.isAutoCaptchaEnabled = autoCaptcha
        if let turnSessionCount { settings.turnSessionCount = TURNSettings.normalizedSessions(turnSessionCount) }
        turnSettings.sessionCount = settings.effectiveTURNSessionCount
        settings.isAutoReconnectOnDropEnabled = autoRecovery
        settings.connectOnDemand = autoRecovery
        settings.recoveryCheckInterval = 30
        settings.turnCheckInterval = TURNHealthCheckPolicy.interval(turnCheckInterval)
        settings.recoveryMaxRetries = 5
        settings.recoveryNotificationsEnabled = false
        save()
    }

    func restoreSelection(_ configurations: [SimpleConfiguration], profileID: String?) {
        guard let configuration = configurations.first(where: { $0.id == profileID }) else { return }
        profiles = [configuration.profile]
        activeProfileId = configuration.id
        turnSettings = configuration.turnSettings
        turnSettings.sessionCount = settings.effectiveTURNSessionCount
    }

    func select(_ profile: VPNProfile) { activeProfileId = profile.id }
    func save() {
        AppGroup.defaults.set(try? JSONEncoder().encode(turnSettings), forKey: AppGroup.turnSettingsKey)
        AppGroup.defaults.set(try? JSONEncoder().encode(settings), forKey: AppGroup.settingsKey)
        AppGroup.defaults.set(activeProfileId, forKey: AppGroup.activeProfileKey)
    }

    func prepare(_ configuration: SimpleConfiguration) throws {
        let value = try configuration.validated(forConnection: true)
        try PanelAccess.require(value.profile.panelAccess)
        if value.mode == .dns { try ManagedDNSStore.save(value.dns) }
        RecoveryTransportStore.enabled = false
        let autoCaptcha = turnSettings.isAutoCaptchaEnabled
        turnSettings = value.turnSettings
        turnSettings.sessionCount = settings.effectiveTURNSessionCount
        turnSettings.isAutoCaptchaEnabled = autoCaptcha
        AppGroup.defaults.set(value.wrapKey, forKey: "simple.turn.wrapKey")
        profiles = [value.profile]
        select(value.profile)
        save()
    }

    func writeActiveConfiguration(profile requestedProfile: VPNProfile? = nil) -> Bool {
        guard let profile = requestedProfile ?? activeProfile, profile.isValid,
              let url = AppGroup.activeConfigURL else { return false }
        do {
            let json = XrayConfigurationBuilder.build(profile: profile, settings: settings)
            try Data(json.utf8).write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
            AppGroup.defaults.set(json, forKey: AppGroup.activeConfigKey)
            return true
        } catch { RuntimeLog.write("Configuration write failed: \(error.localizedDescription)"); return false }
    }
}
