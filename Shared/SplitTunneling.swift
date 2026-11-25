import Foundation
import Darwin
import CryptoKit

enum TemporaryFullTunnelPolicy {
    static let minutes = [5, 15, 30, 60, 0]
    static let defaultMinutes = 15
    static let stateKey = "temporaryFullTunnel.v1"
    static func supported(isTURN: Bool, isDNS: Bool, isAmnezia: Bool, amneziaSplit: Bool) -> Bool {
        !isDNS && (isTURN || (isAmnezia && amneziaSplit))
    }
    static func applying(to saved: AppSettings, isTURN: Bool, isDNS: Bool, isAmnezia: Bool, full: Bool) -> AppSettings {
        var value = saved
        if full || !supported(isTURN: isTURN, isDNS: isDNS, isAmnezia: isAmnezia, amneziaSplit: saved.effectiveAmneziaSplitEnabled) {
            value.splitTunneling?.mode = .disabled
        }
        return value
    }
}

struct TemporaryFullTunnelState: Codable {
    var profileID: String
    var enabled = false
    var pending = false
}

enum SplitTunnelMode: String, Codable, CaseIterable, Identifiable {
    case disabled, bypassSelected, tunnelSelected
    var id: String { rawValue }
    var title: String {
        switch self {
        case .disabled: return "Off"
        case .bypassSelected: return "Bypass selected addresses"
        case .tunnelSelected: return "Tunnel selected addresses only"
        }
    }
    var detail: String {
        switch self {
        case .disabled: return "All internet traffic uses the selected tunnel. Both lists are retained."
        case .bypassSelected: return "Addresses in this list connect directly. Everything else uses the tunnel."
        case .tunnelSelected: return "Only addresses in this list use the tunnel. Everything else connects directly."
        }
    }
}

struct SplitTunnelEntry: Codable, Equatable, Identifiable {
    var address: String
    var networks: [String] = []
    var isNetworkGroup = false
    var id: String { (isNetworkGroup ? "group:" : "") + address }
    var isIP: Bool { !isNetworkGroup && SplitTunnelAddress.isIP(address) }
}

struct SplitTunnelSettings: Codable, Equatable {
    var mode: SplitTunnelMode = .disabled
    var bypassEntries: [SplitTunnelEntry] = []
    var tunnelEntries: [SplitTunnelEntry] = []
    // Optional for settings/backups/packages written before this feature.
    var pushNotifications: PushNotificationSettings?
    var activeEntries: [SplitTunnelEntry] {
        switch mode {
        case .disabled: return []
        case .bypassSelected: return bypassEntries
        case .tunnelSelected: return tunnelEntries
        }
    }
    var domains: [String] { activeEntries.filter { !$0.isIP && !$0.isNetworkGroup && $0.networks.isEmpty }.map { "domain:" + $0.address } }
    var dnsDomains: [String] { activeEntries.filter { !$0.isIP && !$0.isNetworkGroup }.map { "domain:" + $0.address } }
    var networks: [String] {
        Array(Set(activeEntries.flatMap { ($0.isIP ? [$0.address] : []) + $0.networks })).sorted()
    }
    mutating func setEntries(_ entries: [SplitTunnelEntry], for mode: SplitTunnelMode) {
        switch mode {
        case .disabled: break
        case .bypassSelected: bypassEntries = entries
        case .tunnelSelected: tunnelEntries = entries
        }
    }
    func validated() throws -> Self {
        var value = self
        value.bypassEntries = try SplitTunnelImport.normalized(bypassEntries)
        value.tunnelEntries = try SplitTunnelImport.normalized(tunnelEntries)
        return value
    }
}

struct PushNotificationSettings: Codable, Equatable {
    var apple = false
    var google = false
    var enabled: Bool { apple || google }
}

// Catalogue 1: device endpoints from Apple APNs / Firebase network documentation.
// Keep it independent of imported lists. Dedicated FCM ports also cover cached
// IPs and absent SNI; HTTPS is restricted to the documented hostnames.
enum PushNotificationRouting {
    static let catalogVersion = 1
    static let appleNetworks = ["17.249.0.0/16", "17.252.0.0/16", "17.57.144.0/22", "17.188.128.0/18", "17.188.20.0/23",
                                "2620:149:a44::/48", "2403:300:a42::/48", "2403:300:a51::/48", "2a01:b740:a42::/48"]
    static let googleHosts = ["mtalk.google.com", "mtalk4.google.com", "mtalk-staging.google.com", "mtalk-dev.google.com"]
        + (1...8).map { "alt\($0)-mtalk.google.com" }
        + ["android.apis.google.com", "device-provisioning.googleapis.com", "firebaseinstallations.googleapis.com"]
    static func domains(_ push: PushNotificationSettings) -> [String] {
        (push.apple ? ["domain:push.apple.com"] : []) + (push.google ? googleHosts.map { "full:" + $0 } : [])
    }
    static func rules(_ push: PushNotificationSettings, tags: [String], proxy: String = "proxy") -> [[String: Any]] {
        let base: [String: Any] = ["type": "field", "inboundTag": tags, "network": "tcp", "outboundTag": proxy]
        func rule(_ fields: [String: Any]) -> [String: Any] { base.merging(fields) { _, new in new } }
        var result: [[String: Any]] = []
        if push.apple {
            result += [rule(["domain": ["domain:push.apple.com"], "port": "443,5223"]),
                       rule(["ip": appleNetworks, "port": "443,5223"])]
        }
        if push.google {
            result += [rule(["port": "5228-5230"]), rule(["domain": googleHosts.map { "full:" + $0 }, "port": "443"])]
        }
        return result
    }
    static func applyingDNS(to root: [String: Any], push: PushNotificationSettings, remote: String) -> [String: Any] {
        guard push.enabled else { return root }
        var result = root, routing = root["routing"] as? [String: Any] ?? [:], dns = root["dns"] as? [String: Any] ?? [:]
        var rules = routing["rules"] as? [[String: Any]] ?? []
        rules.insert(["type": "field", "inboundTag": ["kindly-dns-push"], "outboundTag": "proxy"], at: 0)
        routing["rules"] = rules
        var servers = dns["servers"] as? [Any] ?? []
        let address = remote.isEmpty ? "tcp://1.1.1.1:53" : remote
        let stream = address.contains("://") || address == "localhost" ? address
            : "tcp://" + (SplitTunnelAddress.isIP(address) && address.contains(":") ? "[\(address)]:53" : address)
        servers.insert(["address": stream, "domains": domains(push), "tag": "kindly-dns-push", "skipFallback": true], at: 0)
        dns["servers"] = servers; dns["disableFallbackIfMatch"] = true
        result["routing"] = routing; result["dns"] = dns
        return result
    }
}

struct SplitTunnelError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

enum SplitTunnelAddress {
    static func isIP(_ address: String) -> Bool {
        let host = address.components(separatedBy: "/")[0]
        var v4 = in_addr(); var v6 = in6_addr()
        return inet_pton(AF_INET, host, &v4) == 1 || inet_pton(AF_INET6, host, &v6) == 1
    }

    static func normalize(_ raw: String) throws -> String {
        var value = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if value.contains("://") {
            guard let url = URL(string: value), ["https", "http"].contains(url.scheme ?? ""),
                  let host = url.host, url.user == nil, url.password == nil else { throw invalid(raw) }
            value = host
        }
        if value.hasPrefix("[") && value.hasSuffix("]") { value = String(value.dropFirst().dropLast()) }
        let parts = value.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count <= 2, !value.isEmpty else { throw invalid(raw) }
        var v4 = in_addr(); var v6 = in6_addr()
        let family: Int32
        var bytes: [UInt8]
        if inet_pton(AF_INET, String(parts[0]), &v4) == 1 {
            family = AF_INET; bytes = withUnsafeBytes(of: &v4) { Array($0) }
        } else if inet_pton(AF_INET6, String(parts[0]), &v6) == 1 {
            family = AF_INET6; bytes = withUnsafeBytes(of: &v6) { Array($0) }
        } else {
            guard parts.count == 1, !value.contains(":"), !value.contains(where: { $0.isWhitespace }) else { throw invalid(raw) }
            if value.hasPrefix("*.") { value = String(value.dropFirst(2)) }
            if value.hasSuffix(".") { value.removeLast() }
            guard let host = URL(string: "https://" + value)?.host?.lowercased(), host.utf8.count <= 253 else { throw invalid(raw) }
            let labels = host.split(separator: ".", omittingEmptySubsequences: false)
            guard labels.count >= 2, !host.allSatisfy({ $0.isNumber || $0 == "." }), labels.allSatisfy({ label in
                !label.isEmpty && label.utf8.count <= 63 && label.first != "-" && label.last != "-" &&
                label.utf8.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }
            }) else { throw invalid(raw) }
            return host
        }
        var suffix = ""
        if parts.count == 2 {
            guard let prefix = Int(parts[1]), (0...(bytes.count * 8)).contains(prefix),
                  !parts[1].isEmpty, parts[1].utf8.allSatisfy({ (48...57).contains($0) }) else { throw invalid(raw) }
            for index in bytes.indices {
                let bits = min(8, max(0, prefix - index * 8))
                bytes[index] &= bits == 0 ? 0 : UInt8(0xff << (8 - bits) & 0xff)
            }
            suffix = "/\(prefix)"
        }
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let result = bytes.withUnsafeBytes { inet_ntop(family, $0.baseAddress, &buffer, socklen_t(buffer.count)) }
        guard result != nil else { throw invalid(raw) }
        return String(cString: buffer) + suffix
    }

    private static func invalid(_ raw: String) -> SplitTunnelError {
        SplitTunnelError(message: "Invalid address: \(raw.prefix(100)). Enter a domain, IP address or network, for example 192.168.1.0/24.")
    }
}

enum SplitTunnelImport {
    static let maximumFileSize = 5 * 1024 * 1024
    static func json(_ data: Data) throws -> [SplitTunnelEntry] {
        guard data.count <= maximumFileSize else { throw SplitTunnelError(message: "The file is too large. The maximum size is 5 MB.") }
        let object: Any
        do { object = try JSONSerialization.jsonObject(with: data) }
        catch { throw SplitTunnelError(message: "Could not read the JSON. Choose an address list file from iplist.opencck.org.") }
        let entries: [SplitTunnelEntry]
        if let groups = object as? [String: [String]] {
            entries = groups.sorted { $0.key < $1.key }.map {
                SplitTunnelEntry(address: $0.key, networks: $0.value,
                                 isNetworkGroup: !$0.key.contains(".") && !SplitTunnelAddress.isIP($0.key))
            }
        } else if let addresses = object as? [String] {
            entries = addresses.map { SplitTunnelEntry(address: $0) }
        } else {
            throw SplitTunnelError(message: "Expected JSON such as {\"example.com\": [\"203.0.113.0/24\"]} or an array of addresses.")
        }
        guard !entries.isEmpty else { throw SplitTunnelError(message: "JSON contains no addresses.") }
        return try normalized(entries)
    }
    static func manual(_ text: String) throws -> [SplitTunnelEntry] {
        let parts = text.components(separatedBy: .whitespacesAndNewlines.union(CharacterSet(charactersIn: ",;"))).filter { !$0.isEmpty }
        guard !parts.isEmpty else { throw SplitTunnelError(message: "Enter at least one address.") }
        return try normalized(parts.map { SplitTunnelEntry(address: $0) })
    }
    static func normalized(_ entries: [SplitTunnelEntry]) throws -> [SplitTunnelEntry] {
        guard entries.count <= 20_000, entries.reduce(0, { $0 + $1.networks.count }) <= 100_000 else {
            throw SplitTunnelError(message: "The list contains too many addresses.")
        }
        var groups: [String: SplitTunnelEntry] = [:]
        for entry in entries {
            let address: String
            if entry.isNetworkGroup {
                address = entry.address.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                guard !address.isEmpty, address.count <= 100, !entry.networks.isEmpty,
                      address.allSatisfy({ $0.isLetter || $0.isNumber || " _-@".contains($0) }) else {
                    throw SplitTunnelError(message: "Invalid IP network group name: \(entry.address.prefix(100)).")
                }
            } else { address = try SplitTunnelAddress.normalize(entry.address) }
            let id = (entry.isNetworkGroup ? "group:" : "") + address
            var networks = Set(groups[id]?.networks ?? [])
            for raw in entry.networks {
                let network = try SplitTunnelAddress.normalize(raw)
                guard SplitTunnelAddress.isIP(network) else { throw SplitTunnelError(message: "The network list for \(address) must contain only IP addresses or CIDR networks.") }
                networks.insert(network)
            }
            groups[id] = SplitTunnelEntry(address: address, networks: Array(networks).sorted(), isNetworkGroup: entry.isNetworkGroup)
        }
        return groups.values.sorted { $0.id < $1.id }
    }
}

enum SplitTunnelRouting {
    // Public runtime diagnostics contain counts/fingerprints, never addresses,
    // domains, connection keys or subscription credentials.
    static func diagnosticJSON(root: [String: Any], settings: AppSettings) -> String {
        let split = settings.splitTunneling ?? SplitTunnelSettings()
        let networks = split.networks
        func fingerprint(_ value: Any) -> String {
            guard let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes]) else { return "unavailable" }
            return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        }
        let summary: [String: Any] = [
            "splitMode": split.mode.rawValue, "entries": split.activeEntries.count,
            "ipv4Zones": networks.filter { !$0.contains(":") }.count,
            "ipv6Zones": networks.filter { $0.contains(":") }.count,
            "ipv6Enabled": settings.ipv6Enabled, "networkSHA256": fingerprint(networks),
            "pushCatalogVersion": PushNotificationRouting.catalogVersion,
            "pushApple": split.pushNotifications?.apple ?? false, "pushGoogle": split.pushNotifications?.google ?? false,
            "policySHA256": fingerprint(["routing": root["routing"] ?? [:], "dns": root["dns"] ?? [:]])
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: summary, options: [.sortedKeys]) else { return "{}" }
        return String(decoding: data, as: UTF8.self)
    }

    // The saved configuration remains the baseline. Only the extension applies
    // the current split policy at startup, also for iOS on-demand connections.
    static func applying(to root: [String: Any], settings: AppSettings) -> [String: Any] {
        let split = settings.splitTunneling ?? SplitTunnelSettings()
        let push = split.pushNotifications ?? PushNotificationSettings()
        guard split.mode != .disabled || push.enabled else { return root }
        var result = root
        var routing = root["routing"] as? [String: Any] ?? [:]
        let existing = routing["rules"] as? [[String: Any]] ?? []
        let tags = ["in_proxy", "kindly-socks"]
        let selected = split.mode == .bypassSelected ? "direct" : "proxy"
        let fallback = split.mode == .bypassSelected ? "proxy" : "direct"
        var rules: [[String: Any]] = [
            ["type": "field", "inboundTag": tags, "port": "53", "outboundTag": "kindly-dns"],
        ]
        if !settings.ipv6Enabled { rules.append(["type": "field", "inboundTag": tags, "ip": ["::/0"], "outboundTag": "block"]) }
        if settings.bypassLocalNetwork {
            rules.append(["type": "field", "inboundTag": tags, "ip": ["geoip:private"], "outboundTag": "direct"])
        }
        rules += PushNotificationRouting.rules(push, tags: tags)
        // With split disabled, retain every baseline rule and DNS setting.
        if split.mode == .disabled {
            routing["rules"] = rules + existing; result["routing"] = routing
            return PushNotificationRouting.applyingDNS(to: result, push: push, remote: settings.remoteDNS)
        }
        // A group label with networks is a DNS hint, not a packet-domain rule.
        // Established destinations retain their actual IP for CIDR matching.
        if !split.domains.isEmpty { rules.append(["type": "field", "inboundTag": tags, "domain": split.domains, "outboundTag": selected]) }
        if !split.networks.isEmpty { rules.append(["type": "field", "inboundTag": tags, "ip": split.networks, "outboundTag": selected]) }
        rules.append(["type": "field", "inboundTag": tags, "network": "tcp,udp", "outboundTag": fallback])
        // Health probes, native transports and DNS upstream tags retain their
        // baseline routes. Only traffic arriving from apps uses the split list.
        routing["rules"] = rules + existing
        routing["domainStrategy"] = "AsIs"
        result["routing"] = routing
        var dns = root["dns"] as? [String: Any] ?? [:]
        var servers: [[String: Any]] = []
        let remote = settings.remoteDNS.isEmpty ? "tcp://1.1.1.1:53" : settings.remoteDNS
        let direct = settings.directDNS.isEmpty ? "tcp://1.1.1.1:53" : settings.directDNS
        if !split.dnsDomains.isEmpty {
            servers.append(["address": selected == "direct" ? direct : remote, "domains": split.dnsDomains,
                            "tag": selected == "direct" ? "kindly-dns-direct" : "kindly-dns-query", "skipFallback": true])
        }
        servers.append(["address": fallback == "direct" ? direct : remote,
                        "tag": fallback == "direct" ? "kindly-dns-direct" : "kindly-dns-query"])
        // Unselected names prefer physical DNS. A failed physical resolver may
        // use proxy DNS, while a matched proxy hint never leaks to physical DNS.
        if fallback == "direct" { servers.append(["address": remote, "tag": "kindly-dns-query"]) }
        dns["servers"] = servers
        dns["disableFallbackIfMatch"] = true
        result["dns"] = dns
        return PushNotificationRouting.applyingDNS(to: result, push: push, remote: settings.remoteDNS)
    }
}
