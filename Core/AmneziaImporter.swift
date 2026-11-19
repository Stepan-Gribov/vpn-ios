import Foundation
import zlib
import Darwin

/// Amnezia's vpn:// format is URL-safe Base64 containing Qt qCompress data:
/// four big-endian size bytes followed by a zlib stream. Never expand unbounded input.
enum AmneziaImporter {
    static let maximumSize = 2 * 1024 * 1024
    static let socksPort = 9004
    struct Connection {
        var profile: VPNProfile
        var title: String
        var protocolName: String
    }

    static func parse(_ input: String) throws -> Connection { try parse(input, depth: 0) }

    private static func parse(_ input: String, depth: Int) throws -> Connection {
        guard depth < 4 else { throw failure("The Amnezia key has too many nested configurations.") }
        let text = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, text.utf8.count <= maximumSize else { throw failure("Paste your Amnezia connection key or configuration (up to 2 MB).") }
        if text.hasPrefix("[Interface]") { return try wireguard(text, title: nil) }
        var data = Data(text.utf8)
        if text.hasPrefix("vpn://") {
            var base64 = String(text.dropFirst(6)).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
            base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
            guard let decoded = Data(base64Encoded: base64) else { throw failure("The Amnezia key is incomplete. Copy the entire vpn:// key.") }
            data = decoded
            if decoded.count >= 6, decoded[4] == 0x78 {
                let size = decoded.prefix(4).reduce(0) { ($0 << 8) | Int($1) }
                guard (1...maximumSize).contains(size) else { throw failure("The Amnezia key is too large or damaged.") }
                var expanded = Data(count: size); var length = uLongf(size)
                let result = expanded.withUnsafeMutableBytes { output in
                    decoded.dropFirst(4).withUnsafeBytes { compressed in
                        uncompress(output.bindMemory(to: Bytef.self).baseAddress, &length,
                                   compressed.bindMemory(to: Bytef.self).baseAddress, uLong(compressed.count))
                    }
                }
                guard result == Z_OK, length == size else { throw failure("The Amnezia key is damaged. Copy it again.") }
                data = expanded
            }
        }
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw failure("Paste a complete vpn:// key or an AmneziaWG configuration.") }
        if let wrapped = root["key"] as? String, wrapped.hasPrefix("vpn://") || wrapped.hasPrefix("[Interface]") {
            return try parse(wrapped, depth: depth + 1)
        }
        let title = root["description"] as? String
        if let containers = root["containers"] as? [[String: Any]] {
            let selected = root["defaultContainer"] as? String
            let container = containers.first { $0["container"] as? String == selected } ?? containers.first
            guard let container else { throw failure("The key contains no connection configuration.") }
            for name in ["awg", "wireguard", "xray"] {
                guard let section = container[name] as? [String: Any] else { continue }
                var config = section["last_config"] as? [String: Any]
                if let raw = section["last_config"] as? String, let bytes = raw.data(using: .utf8) {
                    config = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any]
                    if config == nil, raw.hasPrefix("[Interface]") { return try wireguard(raw, title: title) }
                }
                guard let config else { throw failure("This is a server administration key. Export a connection key from Amnezia → Share.") }
                if let native = config["config"] as? String {
                    if name == "xray" { return try xray(native, title: title) }
                    return try wireguard(native, title: title)
                }
                if name == "xray" { return try xrayObject(config, title: title) }
                throw failure("The key has no client configuration. Export a connection key from Amnezia → Share.")
            }
            throw failure("This key uses an unsupported protocol. Export an AmneziaWG, WireGuard or Xray connection key from Amnezia.")
        }
        if root["outbounds"] != nil { return try xrayObject(root, title: title) }
        throw failure("This key requires the Amnezia subscription service. Export an AmneziaWG connection configuration from Amnezia.")
    }

    private static func xray(_ text: String, title: String?) throws -> Connection {
        guard let data = text.data(using: .utf8), let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw failure("The Xray configuration is damaged.") }
        return try xrayObject(root, title: title)
    }

    private static func xrayObject(_ root: [String: Any], title: String?) throws -> Connection {
        // Import only the connection outbound. Device-specific inbounds, DNS and
        // routing from another client must not override this app's split rules.
        guard let outbounds = root["outbounds"] as? [[String: Any]], let outbound = outbounds.first(where: {
            ["vless", "vmess", "trojan", "shadowsocks", "wireguard"].contains($0["protocol"] as? String ?? "")
        }), outbound["proxySettings"] == nil else { throw failure("No supported standalone Xray connection was found in this key.") }
        var clean = outbound; clean["tag"] = "proxy"
        let bytes = try JSONSerialization.data(withJSONObject: clean, options: [.sortedKeys])
        var profile = VPNProfile(); profile.kind = .custom; profile.rawOutboundJSON = String(decoding: bytes, as: UTF8.self)
        let settings = outbound["settings"] as? [String: Any] ?? [:]
        let server = ((settings["vnext"] ?? settings["servers"]) as? [[String: Any]])?.first
        profile.address = server?["address"] as? String ?? "Amnezia"
        profile.port = server?["port"] as? Int ?? 443
        return Connection(profile: profile, title: displayName(title, fallback: profile.address), protocolName: "Xray")
    }

    private static func wireguard(_ text: String, title: String?) throws -> Connection {
        var section = ""; var fields = [String: String](); var peer = [String: String](); var peers = 0
        for raw in text.components(separatedBy: .newlines) {
            let line = raw.components(separatedBy: "#")[0].trimmingCharacters(in: .whitespaces)
            if line.isEmpty { continue }
            if line.hasPrefix("[") {
                section = line.lowercased()
                guard ["[interface]", "[peer]"].contains(section) else { throw failure("The configuration contains an unsupported section.") }
                if section == "[peer]" { peers += 1 }
                continue
            }
            let pair = line.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard pair.count == 2, !section.isEmpty else { throw failure("The AmneziaWG configuration is incomplete.") }
            let name = pair[0].trimmingCharacters(in: .whitespaces).lowercased()
            let value = pair[1].trimmingCharacters(in: .whitespaces)
            let existing = section == "[interface]" ? fields[name] : peer[name]
            guard existing == nil || existing == value else { throw failure("The configuration contains conflicting values for \(name).") }
            if section == "[interface]" { fields[name] = value } else { peer[name] = value }
        }
        guard peers == 1 else { throw failure("Export a connection configuration with exactly one server.") }
        let privateKey = try key(fields["privatekey"], name: "PrivateKey")
        let publicKey = try key(peer["publickey"], name: "PublicKey")
        guard let endpoint = peer["endpoint"], let url = URLComponents(string: "udp://" + endpoint),
              let host = url.host, !host.isEmpty, let port = url.port, (1...65535).contains(port),
              url.user == nil, url.password == nil, url.path.isEmpty, url.query == nil, url.fragment == nil else { throw failure("The Amnezia server address or port is missing.") }
        let addresses = try list(fields["address"]).map { raw -> String in
            let pieces = raw.split(separator: "/")
            guard pieces.count == 2, let mask = Int(pieces[1]), validIP(String(pieces[0])),
                  (0...(pieces[0].contains(":") ? 128 : 32)).contains(mask) else { throw failure("The Amnezia interface address is invalid.") }
            return String(pieces[0])
        }
        guard !addresses.isEmpty else { throw failure("The Amnezia interface address is missing.") }
        let dns = list(fields["dns"]).filter(validIP)
        let mtu = Int(fields["mtu"] ?? "1280") ?? 0
        guard (576...1500).contains(mtu) else { throw failure("The Amnezia MTU is invalid.") }
        let mappings = ["jc":"jc", "jmin":"jmin", "jmax":"jmax", "s1":"s1", "s2":"s2", "s3":"s3", "s4":"s4",
                        "h1":"h1", "h2":"h2", "h3":"h3", "h4":"h4", "i1":"i1", "i2":"i2", "i3":"i3", "i4":"i4", "i5":"i5",
                        "contentpaddingaddition":"content_padding_addition", "rekeyaftertime":"rekey_after_time", "rekeytimeout":"rekey_timeout",
                        "rejectaftertime":"reject_after_time", "keepalivetimeout":"keepalive_timeout", "maxhandshakeattempts":"max_handshake_attempts",
                        "randomtrailers":"random_trailers", "disablecookies":"disable_cookies"]
        let ignored = Set(["address", "dns", "privatekey", "mtu", "listenport"])
        for field in fields.keys where mappings[field] == nil && field != "headerprotectionkey" && !ignored.contains(field) {
            throw failure("Unsupported Amnezia setting: \(field). Export a client connection configuration.")
        }
        var uapi = "private_key=\(privateKey)\n"
        for (field, name) in mappings.sorted(by: { $0.key < $1.key }) {
            if var value = fields[field], !value.isEmpty {
                if ["randomtrailers", "disablecookies"].contains(field) {
                    switch value.lowercased() {
                    case "on", "yes", "true", "1": value = "true"
                    case "off", "no", "false", "0": value = "false"
                    default: throw failure("Invalid Amnezia switch: \(field).")
                    }
                }
                guard !value.contains(where: { $0.isNewline || $0 == "\0" }) else { throw failure("Invalid Amnezia parameter.") }
                uapi += "\(name)=\(value)\n"
            }
        }
        if let value = fields["headerprotectionkey"], !value.isEmpty { uapi += "header_protection_key=\(try key(value, name: "HeaderProtectionKey"))\n" }
        uapi += "replace_peers=true\npublic_key=\(publicKey)\n"
        if let value = peer["presharedkey"], !value.isEmpty { uapi += "preshared_key=\(try key(value, name: "PresharedKey"))\n" }
        uapi += "endpoint=\(endpoint)\nreplace_allowed_ips=true\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\n"
        // Shared split tunneling owns destination selection. The imported peer
        // remains a full tunnel, while the Xray router chooses direct vs tunnel.
        let keepalive = peer["persistentkeepalive"] ?? "25"
        guard keepalive.range(of: "^[0-9]+(-[0-9]+)?$", options: .regularExpression) != nil else { throw failure("Invalid Amnezia keepalive.") }
        uapi += "persistent_keepalive_interval=\(keepalive)\n"
        let runtime: [String: Any] = ["addresses": addresses, "dns": dns.isEmpty ? ["1.1.1.1"] : dns, "mtu": mtu, "uapi": uapi]
        let data = try JSONSerialization.data(withJSONObject: runtime, options: [.sortedKeys])
        var profile = VPNProfile(); profile.kind = .socks; profile.address = "127.0.0.1"; profile.port = socksPort; profile.security = .none
        profile.amneziaRuntimeJSON = String(decoding: data, as: UTF8.self)
        let isAWG = fields.keys.contains { mappings[$0] != nil || $0 == "headerprotectionkey" }
        return Connection(profile: profile, title: displayName(title, fallback: endpoint), protocolName: isAWG ? "AmneziaWG" : "WireGuard")
    }

    private static func key(_ value: String?, name: String) throws -> String {
        guard let value, let data = Data(base64Encoded: value), data.count == 32, data.contains(where: { $0 != 0 }) else { throw failure("The \(name) in the Amnezia key is missing or invalid.") }
        return data.map { String(format: "%02x", $0) }.joined()
    }
    private static func validIP(_ value: String) -> Bool {
        var v4 = in_addr(); var v6 = in6_addr()
        return inet_pton(AF_INET, value, &v4) == 1 || inet_pton(AF_INET6, value, &v6) == 1
    }
    private static func list(_ value: String?) -> [String] { (value ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty } }
    private static func displayName(_ value: String?, fallback: String) -> String {
        let name = value?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return name.isEmpty ? fallback : String(name.prefix(100))
    }
    private static func failure(_ message: String) -> ConfigurationError { ConfigurationError(message) }
}
