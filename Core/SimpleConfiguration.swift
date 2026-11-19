import Foundation

enum TunnelMode: String, Codable, CaseIterable, Identifiable {
    case amnezia, turn, dns
    var id: String { rawValue }
    var title: String {
        switch self {
        case .amnezia: return "Amnezia"
        case .turn: return "TURN proxy"
        case .dns: return "DNS tunnel"
        }
    }
    var caption: String {
        switch self {
        case .amnezia: return "Amnezia VPN"
        case .turn: return "VK Calls · TURN"
        case .dns: return "DNS tunneling · DNSTT"
        }
    }
}

/// Each row owns its complete configuration. Only the selected row is staged
/// into the upstream runtime's singleton storage immediately before connecting.
struct SimpleConfiguration: Codable, Identifiable, Equatable {
    static let builtInDNSID = ManagedDNSSettings.builtInProfileID
    var id = UUID().uuidString
    var mode: TunnelMode = .turn
    var callLink = ""
    var server = ""
    var vlessID = ""
    var wrapKey = ""
    var dns = ManagedDNSSettings()
    var amneziaKey: String?
    var amneziaName: String?
    var amneziaProtocol: String?
    var managed: PanelManagedProfile?

    var isBuiltInDNS: Bool { id.lowercased() == Self.builtInDNSID }
    static func builtInDNS() throws -> Self {
        let transport = try PanelContract.bundled().dns
        var value = Self(); value.id = builtInDNSID; value.mode = .dns
        value.dns.name = "Built-in DNS"; value.dns.domain = transport.domain
        value.dns.publicKey = transport.publicKey; value.dns.resolver = transport.resolver
        value.dns.sessionCount = transport.sessionCount; value.dns.autoDetectResolver = transport.autoDetectResolver
        value.dns.savedResolvers = transport.savedResolvers
        value.dns.useWiFiResolver = transport.useWiFiResolver; value.dns.wifiResolver = transport.wifiResolver
        return try value.validated()
    }

    var title: String { isBuiltInDNS ? "Built-in DNS" : (managed?.title ?? (mode == .amnezia ? (amneziaName ?? "Amnezia") : (mode == .turn ? server : dns.domain))) }
    var detail: String {
        if isBuiltInDNS { return "Always available · DNSTT" }
        if let managed { return [managed.location, "Subscription"].filter { !$0.isEmpty }.joined(separator: " · ") }
        return mode == .amnezia ? (amneziaProtocol ?? "Amnezia VPN") : (mode == .turn ? "VK Calls" : "DNSTT · \(dns.tunnelType.uppercased())")
    }

    func validated(forConnection: Bool = false) throws -> Self {
        var result = self
        if mode == .turn {
            guard let link = TURNSettings.normalizeVKCallLink(callLink) else {
                throw ConfigurationError("Enter a VK call link: https://vk.com/call/join/…")
            }
            result.callLink = link
            result.server = try Self.normalizedServer(server)
            result.vlessID = vlessID.trimmingCharacters(in: .whitespacesAndNewlines)
            if forConnection || !result.vlessID.isEmpty {
                guard UUID(uuidString: result.vlessID) != nil else {
                    throw ConfigurationError("Your server's VLESS UUID is required to connect. Enter it in the profile settings.")
                }
            }
            result.wrapKey = wrapKey.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            guard result.wrapKey.isEmpty || result.wrapKey.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else {
                throw ConfigurationError("The transport key must contain 64 hexadecimal characters or be blank.")
            }
        } else if mode == .amnezia {
            let connection = try AmneziaImporter.parse(amneziaKey ?? "")
            result.amneziaKey = amneziaKey?.trimmingCharacters(in: .whitespacesAndNewlines)
            result.amneziaName = connection.title
            result.amneziaProtocol = connection.protocolName
        } else {
            result.dns = try dns.validated()
        }
        return result
    }

    static func normalizedServer(_ raw: String) throws -> String {
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        let withPort: String
        if value.hasPrefix("[") {
            guard let end = value.firstIndex(of: "]") else { throw ConfigurationError("Check the server's IPv6 address.") }
            withPort = value.index(after: end) == value.endIndex ? value + ":56010" : value
        } else {
            let count = value.filter { $0 == ":" }.count
            withPort = count > 1 ? "[\(value)]:56010" : (count == 0 ? value + ":56010" : value)
        }
        guard let normalized = TURNSettings.normalizePeer(withPort),
              let components = URLComponents(string: "udp://" + normalized),
              let host = components.host, !host.isEmpty,
              components.user == nil, components.password == nil,
              components.path.isEmpty, components.query == nil, components.fragment == nil,
              let port = components.port, (1...65535).contains(port) else {
            throw ConfigurationError("Enter the server IP address or hostname. Add a port if needed: 203.0.113.10:56010.")
        }
        return normalized
    }

    var profile: VPNProfile {
        var value: VPNProfile
        switch mode {
        case .amnezia: value = (try? AmneziaImporter.parse(amneziaKey ?? "").profile) ?? VPNProfile()
        case .dns: value = dns.profile
        case .turn: value = VPNProfile()
        }
        value.id = id
        value.name = title
        if let managed {
            value.panelAccess = PanelAccessGrant(subscriptionID: managed.subscriptionID, profileID: id,
                generation: managed.generation, credentialDigest: managed.credentialDigest, expiresAt: managed.expiresAt)
        }
        if mode == .turn {
            value.kind = .vless; value.address = "127.0.0.1"; value.port = 9000
            value.security = .none; value.transport = .tcp; value.credential = vlessID
        }
        return value
    }

    var turnSettings: TURNSettings {
        var value = TURNSettings()
        value.provider = .vk; value.vkCallLink = callLink; value.peer = server
        value.setupWasShown = true
        return value
    }
}

struct ConfigurationError: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

enum TrafficDisplay {
    static func bytes(_ value: Double) -> String {
        let amount = max(0, value)
        if amount < 1_000 { return "\(Int(amount)) B" }
        if amount < 1_000_000 { return String(format: "%.1f KB", amount / 1_000) }
        if amount < 1_000_000_000 { return String(format: "%.1f MB", amount / 1_000_000) }
        return String(format: "%.2f GB", amount / 1_000_000_000)
    }
    static func speed(_ value: Double) -> String { bytes(value) + "/s" }
}
