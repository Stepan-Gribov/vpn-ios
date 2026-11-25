import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

enum ProxyKind: String, Codable, CaseIterable, Identifiable {
    case vmess
    case vless
    case shadowsocks
    case trojan
    case wireguard
    case socks
    case http
    case custom

    var id: String { rawValue }

    var title: String {
        switch self {
        case .shadowsocks: return "Shadowsocks"
        case .wireguard: return "WireGuard"
        case .socks: return "SOCKS"
        default: return rawValue.uppercased()
        }
    }
}

enum TransportKind: String, Codable, CaseIterable, Identifiable {
    case tcp
    case ws
    case grpc
    case xhttp
    case httpUpgrade
    case h2
    case quic
    case kcp

    var id: String { rawValue }
}

enum SecurityKind: String, Codable, CaseIterable, Identifiable {
    case none
    case tls
    case reality
    case xtls

    var id: String { rawValue }
}

struct VPNProfile: Codable, Identifiable, Hashable {
    var panelAccess: PanelAccessGrant?
    var id = UUID().uuidString
    var name = "New profile"
    var kind: ProxyKind = .vless
    var address = ""
    var port = 443
    var credential = ""
    var encryption = "none"
    var flow = ""

    var transport: TransportKind = .tcp
    var path = "/"
    var host = ""
    var headerType = "none"
    var seed = ""
    // Optional so profiles saved by earlier releases continue to decode.
    var grpcServiceName: String?
    var grpcAuthority: String?
    var transportMode: String?
    var xhttpExtra: String?
    var finalMask: String?
    var kcpMTU: Int?
    var kcpTTI: Int?

    var security: SecurityKind = .tls
    var sni = ""
    var fingerprint = "chrome"
    var alpn: String?
    var pinnedCertificateSHA256: String?
    var echConfigList: String?
    var verifyPeerCertByName: String?
    var mldsa65Verify: String?
    var publicKey = ""
    var shortId = ""
    var spiderX = ""
    var allowInsecure = false

    var shadowsocksMethod = "chacha20-ietf-poly1305"
    var shadowsocksPassword = ""

    var amneziaRuntimeJSON: String?

    var wireguardPrivateKey = ""
    var wireguardPeerPublicKey = ""
    var wireguardPreSharedKey = ""
    var wireguardEndpoint = ""
    var wireguardAddresses = ["10.0.0.2/32"]
    var wireguardReserved = ""
    var wireguardMTU = 1280


    var muxEnabled = false
    var packetFragmentation = false
    var rawOutboundJSON = ""
    var composition: ProfileComposition?
    var subscriptionId: String?
    var latencyMilliseconds: Int?
    var lastError: String?

    var isAmnezia: Bool { amneziaRuntimeJSON != nil }

    var isManagedDNS: Bool { kind == .socks && address == "127.0.0.1" && port == ManagedDNSSettings.port }

    var isTURN: Bool {
        isManagedDNS || kind == .vless && ["127.0.0.1", "localhost"].contains(address.lowercased()) && [9000, DNSConnection.port].contains(port)
    }

    var isDNS: Bool { isTURN && port == DNSConnection.port }

    var subtitle: String {
        if isManagedDNS { return "DNSTT / DNS · 127.0.0.1:9002" }
        if isDNS { return "DNS tunnel · fallback connection" }
        if isTURN { return "TURN · \(transport.rawValue.uppercased()) · 127.0.0.1:9000" }
        return "\(kind.title) · \(address):\(port)"
    }

    var isValid: Bool {
        if kind == .custom {
            guard let data = rawOutboundJSON.data(using: .utf8),
                  let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return false }
            return object["protocol"] is String || (object["outbounds"] as? [[String: Any]])?.isEmpty == false
        }
        return !address.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && (1...65_535).contains(port)
    }

    var connectionValidationError: String? {
        guard kind != .custom else { return nil }
        if [.h2, .quic].contains(transport) {
            return "The \(transport.rawValue.uppercased()) transport was removed from this Xray version. Ask your provider for an XHTTP profile or another supported transport."
        }
        return isValid ? nil : "Check the profile address and port."
    }
}

enum DNSConnection {
    static let port = 9001

    static func isKindlySubscription(_ url: URL) -> Bool {
        configuredDNSRecoveryURL.map { url.host == $0.host && url.scheme == "https" } == true &&
            url.user == nil && url.password == nil && (url.port == nil || url.port == 443)
    }

    static func adding(to profiles: [VPNProfile], available: Bool) -> [VPNProfile] {
        guard available else { return profiles }
        var credentials = Set(profiles.filter(\.isDNS).map(\.credential))
        let added = profiles.compactMap { profile -> VPNProfile? in
            guard profile.isTURN, !profile.isDNS, !profile.isManagedDNS, profile.security == .none,
                  profile.transport == .tcp, !profile.credential.isEmpty,
                  credentials.insert(profile.credential).inserted else { return nil }
            var dns = profile
            dns.id = UUID().uuidString
            dns.name = "DNS tunnel"
            dns.address = "127.0.0.1"
            dns.port = port
            dns.latencyMilliseconds = nil
            dns.lastError = nil
            return dns
        }
        return profiles + added
    }

    static func normalized(_ data: Data) throws -> Data {
        guard data.count <= 65_536,
              var root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              root["version"] as? Int == 1,
              let profiles = root["profiles"] as? [[String: Any]], (1...8).contains(profiles.count),
              profiles.allSatisfy({ $0["type"] as? String == "dnstt" }) else {
            throw URLError(.cannotParseResponse)
        }
        root["listen"] = "127.0.0.1:\(port)"
        root.removeValue(forKey: "start_after")
        return try JSONSerialization.data(withJSONObject: root, options: .sortedKeys)
    }
}

struct Subscription: Codable, Identifiable, Hashable {
    var id = UUID().uuidString
    var name = "KindlyVPN"
    var url = ""
    var enabled = true
    var automaticUpdates = true
    var allowInsecureURL = false
    var lastUpdated: Date?
    var profileCount = 0
    var uploadBytes: Int64?
    var downloadBytes: Int64?
    var totalBytes: Int64?
    var expiresAt: Date?
    var updateIntervalMinutes: Int?

    var refreshInterval: Int {
        get { max(15, updateIntervalMinutes ?? 1440) }
        set { updateIntervalMinutes = max(15, newValue) }
    }

    var usedBytes: Int64? {
        guard uploadBytes != nil || downloadBytes != nil else { return nil }
        return max(0, uploadBytes ?? 0) + max(0, downloadBytes ?? 0)
    }
}

enum RoutingMode: String, Codable, CaseIterable, Identifiable {
    case rules
    case global
    case direct

    var id: String { rawValue }

    var title: String {
        switch self {
        case .rules: return "Rule-based"
        case .global: return "All traffic through VPN"
        case .direct: return "Direct connection only"
        }
    }
}

enum DomainStrategy: String, Codable, CaseIterable, Identifiable {
    case asIs = "AsIs"
    case ipIfNonMatch = "IPIfNonMatch"
    case ipOnDemand = "IPOnDemand"

    var id: String { rawValue }
}

enum AppearanceMode: String, Codable, CaseIterable, Identifiable {
    case system
    case light
    case dark

    var id: String { rawValue }
}

struct AppSettings: Codable, Equatable {
    static let defaultAmneziaSplitEnabled = true

    // Optional so builds preceding split tunneling still decode without losing settings.
    var splitTunneling: SplitTunnelSettings?
    // Build 52 starts with split enabled even when an older runtime stored false.
    var amneziaSplitPreference: Bool?
    var fullTunnelMinutes: Int?
    var routingMode: RoutingMode = .rules
    var domainStrategy: DomainStrategy = .ipIfNonMatch
    var remoteDNS = "https://1.1.1.1/dns-query"
    var directDNS = "1.1.1.1"
    var vpnDNS = ["1.1.1.1", "8.8.8.8"]
    var blockAds = false
    var bypassLocalNetwork = true
    var bypassChina = false
    var ipv6Enabled = false
    var fakeDNSEnabled = false
    var sniffingEnabled = true
    var routeOnly = false
    var localProxyEnabled = false
    var socksPort = 10_808
    var socksUsername = ""
    var socksPassword = ""
    var packetFragmentation = false
    var fragmentPackets = "tlshello"
    var fragmentLength = "100-200"
    var fragmentInterval = "10-20"
    var muxEnabled = false
    var muxConcurrency = 8
    var vpnMTU = 1500
    var connectivityTestURL = "https://www.gstatic.com/generate_204"
    var subscriptionUserAgent = "v2rayNG/2.2.6"
    var customDirectDomains = [String]()
    var customBlockedDomains = [String]()
    var customRoutingRules: [RoutingRule]?
    var automaticSubscriptionUpdates = true
    var hideFailedProfiles = false
    var automaticSortAfterTest = false
    var confirmProfileRemoval = true
    var connectOnDemand = false
    // Optional for backwards-compatible decoding of settings saved by older builds.
    var autoReconnectOnDrop: Bool? = false
    var autoReconnectCheckInterval: Int?
    var turnCheckInterval: Int?
    var turnSessionCount: Int?
    var autoReconnectMaxRetries: Int?
    var autoReconnectNotifications: Bool?
    var appearance: AppearanceMode = .system
    var logLevel = "warning"
    var webDAV: WebDAVSettings?

    var effectiveAmneziaSplitEnabled: Bool { amneziaSplitPreference ?? Self.defaultAmneziaSplitEnabled }

    var isAutoReconnectOnDropEnabled: Bool {
        get { autoReconnectOnDrop ?? false }
        set { autoReconnectOnDrop = newValue }
    }

    var recoveryCheckInterval: Int {
        get { min(300, max(15, autoReconnectCheckInterval ?? 30)) }
        set { autoReconnectCheckInterval = min(300, max(15, newValue)) }
    }

    func backgroundProbeInterval(turnProxy: Bool) -> Int {
        turnProxy ? TURNHealthCheckPolicy.interval(turnCheckInterval) : recoveryCheckInterval
    }

    var effectiveTURNSessionCount: Int { TURNSettings.normalizedSessions(turnSessionCount) }

    var recoveryMaxRetries: Int {
        get { min(20, max(1, autoReconnectMaxRetries ?? 5)) }
        set { autoReconnectMaxRetries = min(20, max(1, newValue)) }
    }

    var recoveryNotificationsEnabled: Bool {
        get { autoReconnectNotifications ?? true }
        set { autoReconnectNotifications = newValue }
    }
}

enum TURNProvider: String, Codable, CaseIterable, Identifiable {
    case vk
    case max

    var id: String { rawValue }
    var title: String { self == .vk ? "VK Calls" : "MAX Messenger" }
}

struct TURNSettings: Codable, Equatable {
    static let defaultPeer = "203.0.113.10:56010"
    static let defaultSessions = 10
    static let maximumSessions = 16
    static let sessionChoices = [1, 2, 4, 10, 16]
    static func normalizedSessions(_ value: Int?) -> Int {
        value.flatMap { sessionChoices.contains($0) ? $0 : nil } ?? defaultSessions
    }

    var provider: TURNProvider = .vk
    var subscriptionURL = ""
    var vkCallLink = ""
    var peer = defaultPeer
    var sessionCount = defaultSessions
    var maxPhone = ""
    var maxPeerId = ""
    var maxExternalId = ""
    var setupWasShown = false
    // Optional for backwards-compatible decoding of TURN settings already on-device.
    var autoCaptcha: Bool? = false

    var isAutoCaptchaEnabled: Bool {
        get { false }
        set { autoCaptcha = false }
    }

    func isConfigured(hasMAXToken: Bool) -> Bool {
        switch provider {
        case .vk: return Self.normalizeVKCallLink(vkCallLink) != nil
        case .max: return Int64(maxPeerId).map { $0 > 0 } == true && hasMAXToken
        }
    }

    static func normalizeVKCallLink(_ raw: String) -> String? {
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let components = URLComponents(string: value),
              components.scheme?.lowercased() == "https",
              let host = components.host?.lowercased(),
              ["vk.com", "www.vk.com", "m.vk.com", "vk.ru", "www.vk.ru", "m.vk.ru"].contains(host),
              components.path.contains("/call/join/"),
              !components.path.components(separatedBy: "/call/join/").last.orEmpty.isEmpty else {
            return nil
        }
        return value
    }

    static func normalizePeer(_ raw: String) -> String? {
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let separator = value.lastIndex(of: ":"), separator != value.startIndex else { return nil }
        let host = String(value[..<separator])
        let portText = String(value[value.index(after: separator)...])
        guard !host.contains(where: { $0.isWhitespace }), let port = Int(portText), (1...65_535).contains(port) else {
            return nil
        }
        return "\(host):\(port)"
    }
}

struct RoutingRule: Codable, Identifiable, Equatable {
    var id = UUID().uuidString
    var name = "Rule"
    var enabled = true
    var outbound = "proxy"
    var domains = [String]()
    var ips = [String]()
    var port = ""
    var network = ""
    var protocols = [String]()

    var isValid: Bool {
        ["proxy", "direct", "block"].contains(outbound) &&
            (!domains.isEmpty || !ips.isEmpty || !port.isEmpty || !network.isEmpty || !protocols.isEmpty)
    }
}

struct ProfileComposition: Codable, Hashable {
    enum Mode: String, Codable, CaseIterable, Identifiable {
        case chain, random, roundRobin, leastPing
        var id: String { rawValue }
        var title: String {
            switch self {
            case .chain: return "Proxy chain"
            case .random: return "Group: random server"
            case .roundRobin: return "Group: round robin"
            case .leastPing: return "Group: lowest latency"
            }
        }
    }
    var mode: Mode = .leastPing
    var profileIDs = [String]()
}

struct WebDAVSettings: Codable, Equatable {
    var fileURL = ""
    var username = ""
    var allowHTTP = false
}

extension Optional where Wrapped == String {
    fileprivate var orEmpty: String { self ?? "" }
}

/// Skip retired protocol kinds in saved collections without losing supported profiles.
struct StoredVPNProfile: Decodable {
    let profile: VPNProfile?

    private enum CodingKeys: String, CodingKey { case kind }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let kind = try container.decode(String.self, forKey: .kind)
        profile = ProxyKind(rawValue: kind) == nil ? nil : try VPNProfile(from: decoder)
    }
}


/// Manual DNSTT route, independent of subscription-provided DNS recovery.
struct ManagedDNSSettings: Codable, Equatable {
    static let builtInProfileID = "tndtun.builtin.dns.v1"
    static let port = 9002
    static let profileID = "kindlyvpn_managed_dnstt"
    static let sessionCounts = [1, 2, 4, 8]
    static let defaultSessionCount = 4
    var sessionCount = defaultSessionCount
    var name = "DNS Tunnel"
    var domain = ""
    var resolver = "1.1.1.1:53"
    var autoDetectResolver = true
    var savedResolvers = [String]()
    var useWiFiResolver = false
    var wifiResolver = "8.8.8.8"
    var publicKey = ""
    var tunnelType = "socks5"
    var sshUsername = ""
    var sshPassword = ""
    var sshPrivateKey = ""
    var sshHostKey = ""

    enum CodingKeys: String, CodingKey {
        case name, domain, resolver, savedResolvers, publicKey, tunnelType, sessionCount
        case useWiFiResolver, wifiResolver, autoDetectResolver
        case sshUsername, sshPassword, sshPrivateKey, sshHostKey
    }

    init() {}
    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        name = try values.decodeIfPresent(String.self, forKey: .name) ?? "DNS Tunnel"
        domain = try values.decodeIfPresent(String.self, forKey: .domain) ?? ""
        resolver = try values.decodeIfPresent(String.self, forKey: .resolver) ?? "1.1.1.1:53"
        autoDetectResolver = try values.decodeIfPresent(Bool.self, forKey: .autoDetectResolver) ?? true
        savedResolvers = try values.decodeIfPresent([String].self, forKey: .savedResolvers) ?? []
        useWiFiResolver = try values.decodeIfPresent(Bool.self, forKey: .useWiFiResolver) ?? false
        wifiResolver = try values.decodeIfPresent(String.self, forKey: .wifiResolver) ?? "8.8.8.8"
        publicKey = try values.decodeIfPresent(String.self, forKey: .publicKey) ?? ""
        tunnelType = try values.decodeIfPresent(String.self, forKey: .tunnelType) ?? "socks5"
        sessionCount = try values.decodeIfPresent(Int.self, forKey: .sessionCount) ?? Self.defaultSessionCount
        sshUsername = try values.decodeIfPresent(String.self, forKey: .sshUsername) ?? ""
        sshPassword = try values.decodeIfPresent(String.self, forKey: .sshPassword) ?? ""
        sshPrivateKey = try values.decodeIfPresent(String.self, forKey: .sshPrivateKey) ?? ""
        sshHostKey = try values.decodeIfPresent(String.self, forKey: .sshHostKey) ?? ""
    }

    func validated() throws -> Self {
        var result = self
        guard Self.sessionCounts.contains(sessionCount) else {
            throw SetupError.invalid("Choose 1, 2, 4 or 8 parallel streams.")
        }
        result.name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        if result.name.isEmpty { result.name = "DNS Tunnel" }
        result.domain = domain.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if result.domain.hasSuffix(".") { result.domain.removeLast() }
        guard result.domain.count <= 200,
              result.domain.range(of: #"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"#, options: .regularExpression) != nil else {
            throw SetupError.invalid("Enter the delegated domain for the DNS tunnel.")
        }
        result.publicKey = publicKey.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard result.publicKey.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else {
            throw SetupError.invalid("The DNSTT key must contain 64 hexadecimal characters.")
        }
        result.resolver = try Self.normalizeResolver(resolver)
        if useWiFiResolver {
            do { result.wifiResolver = try Self.normalizeResolver(wifiResolver) }
            catch { throw SetupError.invalid("Wi-Fi DNS: \(error.localizedDescription)") }
        }
        result.savedResolvers = try Array(([result.resolver] + savedResolvers).reduce(into: [String]()) { values, raw in
            let value = try Self.normalizeResolver(raw)
            if !values.contains(value) { values.append(value) }
        }.prefix(32))
        guard ["socks5", "ssh"].contains(tunnelType) else { throw SetupError.invalid("Choose SOCKS5 or SSH.") }
        if tunnelType == "ssh" {
            guard !sshUsername.trimmingCharacters(in: .whitespaces).isEmpty,
                  !sshPassword.isEmpty || !sshPrivateKey.isEmpty else {
                throw SetupError.invalid("Enter an SSH username and a password or private key.")
            }
            guard sshHostKey.hasPrefix("SHA256:"), sshHostKey.count > 12 else {
                throw SetupError.invalid("Enter the SSH server key's SHA256 fingerprint.")
            }
        }
        return result
    }

    static func normalizeResolver(_ raw: String) throws -> String {
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { throw SetupError.invalid("Enter a DNS server.") }
        let host: String
        let port: String
        if value.hasPrefix("["), let end = value.firstIndex(of: "]") {
            host = String(value[value.index(after: value.startIndex)..<end])
            let suffix = String(value[value.index(after: end)...])
            guard suffix.isEmpty || suffix.hasPrefix(":") else { throw SetupError.invalid("Check the DNS server and port.") }
            port = suffix.isEmpty ? "53" : String(suffix.dropFirst())
        } else if value.filter({ $0 == ":" }).count > 1 {
            host = value; port = "53"
        } else {
            let parts = value.split(separator: ":", omittingEmptySubsequences: false)
            host = String(parts[0]); port = parts.count == 2 ? String(parts[1]) : "53"
        }
        guard let number = Int(port), (1...65535).contains(number), isIPAddress(host) else {
            throw SetupError.invalid("Enter a DNS server IP address and port, for example 1.1.1.1:53.")
        }
        return host.contains(":") ? "[\(host)]:\(number)" : "\(host):\(number)"
    }

    private static func isIPAddress(_ host: String) -> Bool {
        var ipv4 = in_addr()
        var ipv6 = in6_addr()
        return host.withCString { inet_pton(AF_INET, $0, &ipv4) == 1 || inet_pton(AF_INET6, $0, &ipv6) == 1 }
    }

    var profile: VPNProfile {
        var value = VPNProfile()
        value.id = Self.profileID; value.name = name; value.kind = .socks
        value.address = "127.0.0.1"; value.port = Self.port; value.security = .none
        return value
    }

    func effectiveResolver(usingWiFi: Bool) -> String {
        useWiFiResolver && usingWiFi ? wifiResolver : resolver
    }

    func runtimePayload(usingWiFi: Bool = false, builtInInterface: String? = nil) throws -> Data {
        let value = try validated()
        var transport: [String: Any] = [
            "domain": value.domain, "resolver": value.effectiveResolver(usingWiFi: usingWiFi), "public_key": value.publicKey,
            "tunnel_type": value.tunnelType, "ssh_username": value.sshUsername,
            "ssh_password": value.sshPassword, "ssh_private_key": value.sshPrivateKey,
            "ssh_host_key": value.sshHostKey, "session_count": value.sessionCount
        ]
        if let builtInInterface {
            let preferred = value.effectiveResolver(usingWiFi: usingWiFi)
            transport["built_in"] = true; transport["physical_interface"] = builtInInterface
            transport["resolvers"] = usingWiFi
                ? ["https://dns.google/dns-query", preferred, "8.8.8.8:53", "https://cloudflare-dns.com/dns-query"]
                : [preferred, "https://dns.google/dns-query", "8.8.8.8:53", "https://cloudflare-dns.com/dns-query"]
        }
        let payload: [String: Any] = ["provider": "managed_dns", "managed_dns": transport]
        return try JSONSerialization.data(withJSONObject: payload)
    }

    enum SetupError: LocalizedError {
        case invalid(String)
        var errorDescription: String? { if case .invalid(let message) = self { return message }; return nil }
    }
}
