import Foundation

/// Portable user configuration. Runtime sockets, diagnostics and iOS VPN
/// permissions are recreated on the destination device, never deserialized.
struct ApplicationBackup: Codable, Equatable, Identifiable {
    enum CodingKeys: String, CodingKey {
        case format, schemaVersion, appVersion, appBuild, createdAt, profiles, mode
        case autoCaptcha, autoRecovery, autoConnectOnLaunch, savedDNSServers, splitTunneling, selectedProfileID, turnCheckInterval
        case applicationDNSServers = "dnsServers"
        case applicationDNSTunnel = "dnsTunnel"
        case amneziaSplitEnabled, fullTunnelMinutes, turnSessionCount
    }
    static let formatName = "TnDtun-backup"
    static let currentSchema = 1
    static let maximumSize = 20 * 1024 * 1024
    var format = Self.formatName
    var schemaVersion = Self.currentSchema
    var appVersion = "1.0"
    var appBuild = ""
    var createdAt = ISO8601DateFormatter().string(from: Date())
    var profiles: [SimpleConfiguration]
    var mode: TunnelMode
    var autoCaptcha: Bool
    var autoRecovery: Bool
    var savedDNSServers: [String]
    var splitTunneling: SplitTunnelSettings
    var selectedProfileID: String?
    // Older backups omit this setting and retain the original 30-second check.
    var turnCheckInterval: Int?
    var applicationDNSServers: [String]?
    var applicationDNSTunnel: PanelDNS?
    var autoConnectOnLaunch: Bool? = nil
    var amneziaSplitEnabled: Bool? = nil
    var fullTunnelMinutes: Int? = nil
    var turnSessionCount: Int? = nil
    var effectiveTURNSessionCount: Int { TURNSettings.normalizedSessions(turnSessionCount) }
    var effectiveTURNCheckInterval: Int { TURNHealthCheckPolicy.interval(turnCheckInterval) }
    var id: String { createdAt }
    var amneziaCount: Int { profiles.filter { $0.mode == .amnezia }.count }
    var turnCount: Int { profiles.filter { $0.mode == .turn }.count }
    var dnsCount: Int { profiles.filter { $0.mode == .dns }.count }

    func validated() throws -> Self {
        guard format == Self.formatName else {
            throw ConfigurationError("This is not a TnDtun backup. On the first device, choose Settings → Transfer → Export all.")
        }
        guard schemaVersion == Self.currentSchema else {
            throw ConfigurationError("This backup format version is not supported. Update TnDtun on both devices.")
        }
        guard profiles.count <= 1000, savedDNSServers.count <= 1000 else {
            throw ConfigurationError("The backup contains too many profiles or DNS servers.")
        }
        if let turnCheckInterval, !(15...300).contains(turnCheckInterval) {
            throw ConfigurationError("The TURN background check interval must be between 15 and 300 seconds.")
        }
        if let turnSessionCount, !TURNSettings.sessionChoices.contains(turnSessionCount) {
            throw ConfigurationError("Invalid number of TURN channels.")
        }
        if let fullTunnelMinutes, !TemporaryFullTunnelPolicy.minutes.contains(fullTunnelMinutes) {
            throw ConfigurationError("Invalid duration for temporary full tunnel.")
        }
        var ids = Set<String>()
        for profile in profiles where !profile.isBuiltInDNS {
            guard !profile.id.isEmpty, profile.id.count <= 200, ids.insert(profile.id).inserted else {
                throw ConfigurationError("The backup contains duplicate or invalid profile IDs.")
            }
        }
        if let selectedProfileID, selectedProfileID != SimpleConfiguration.builtInDNSID, !ids.contains(selectedProfileID) {
            throw ConfigurationError("The selected profile is missing from the backup.")
        }
        var value = self
        value.amneziaSplitEnabled = amneziaSplitEnabled ?? AppSettings.defaultAmneziaSplitEnabled
        value.turnCheckInterval = effectiveTURNCheckInterval
        value.turnSessionCount = effectiveTURNSessionCount
        value.profiles = try profiles.filter { !$0.isBuiltInDNS }.map { profile in var item = profile; item.managed = nil; return try item.validated() }
        if let servers = applicationDNSServers {
            guard servers.count <= 100 else { throw ConfigurationError("Too many application DNS servers.") }
            value.applicationDNSServers = try servers.map(ManagedDNSSettings.normalizeResolver)
        }
        value.applicationDNSTunnel = try applicationDNSTunnel.map(PanelContract.validatedDNS)
        value.splitTunneling = try splitTunneling.validated()
        value.savedDNSServers = try savedDNSServers.reduce(into: [String]()) { result, raw in
            let address = try ManagedDNSSettings.normalizeResolver(raw)
            if !result.contains(address) { result.append(address) }
        }
        return value
    }

    func encoded() throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(validated())
        guard data.count <= Self.maximumSize else { throw ConfigurationError("The backup is too large. The maximum size is 20 MB.") }
        return data
    }

    static func decode(_ data: Data) throws -> Self {
        guard data.count <= maximumSize else { throw ConfigurationError("The backup is too large. The maximum size is 20 MB.") }
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any], root["format"] as? String == formatName else {
            throw ConfigurationError("Choose a JSON file created using Export all in TnDtun.")
        }
        guard root["schemaVersion"] as? Int == currentSchema else {
            throw ConfigurationError("This backup format version is not supported. Update TnDtun on both devices.")
        }
        let value: Self
        do { value = try JSONDecoder().decode(Self.self, from: data) }
        catch { throw ConfigurationError("The backup is damaged or incomplete. Current data is unchanged.") }
        return try value.validated()
    }
}
