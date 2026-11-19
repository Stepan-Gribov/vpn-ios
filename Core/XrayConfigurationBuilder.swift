import Foundation

enum XrayConfigurationBuilder {
    static func probeConfiguration(profile: VPNProfile, settings: AppSettings, localPort: Int, request: HTTPProbeRequest) -> String? {
        guard (1...65535).contains(localPort),
              let data = build(profile: profile, settings: settings).data(using: .utf8),
              var root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        root["inbounds"] = [[
            "tag": "probe", "listen": "127.0.0.1", "port": localPort,
            "protocol": "dokodemo-door",
            "settings": ["address": request.host, "port": request.port, "network": "tcp"],
        ]]
        // Force the measured request through this profile even when the user has
        // bypass rules or direct routing enabled in their normal VPN settings.
        var routing = root["routing"] as? [String: Any] ?? [:]
        var rules = routing["rules"] as? [[String: Any]] ?? []
        rules.insert(["type": "field", "inboundTag": ["probe"], "outboundTag": "proxy"], at: 0)
        routing["rules"] = rules
        root["routing"] = routing
        guard let encoded = try? JSONSerialization.data(withJSONObject: root) else { return nil }
        return String(data: encoded, encoding: .utf8)
    }

    static func build(profile: VPNProfile, settings: AppSettings) -> String {
        var root: [String: Any] = [
            "log": ["loglevel": settings.logLevel],
            "dns": dns(settings),
            "outbounds": outbounds(profile, settings),
            "routing": routing(settings),
            "policy": ["system": [
                "statsInboundDownlink": true,
                "statsInboundUplink": true,
                "statsOutboundDownlink": true,
                "statsOutboundUplink": true,
            ]],
            "stats": [:],
        ]
        if let payload = profile.amneziaRuntimeJSON, let data = payload.data(using: .utf8),
           let runtime = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            root["tndtun_amnezia"] = runtime
        }
        if profile.kind == .custom, let data = profile.rawOutboundJSON.data(using: .utf8),
           let custom = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           var customOutbounds = custom["outbounds"] as? [[String: Any]], !customOutbounds.isEmpty {
            // Retain all outbounds, routing, DNS and transport settings from a full config.
            root = custom
            if !customOutbounds.contains(where: { $0["tag"] as? String == "proxy" }) {
                let primaryTag = customOutbounds[0]["tag"] as? String ?? "kindly-custom-primary"
                customOutbounds[0]["tag"] = primaryTag
                customOutbounds.insert(["tag": "proxy", "protocol": "freedom", "settings": [:],
                                        "proxySettings": ["tag": primaryTag]], at: 0)
            }
            root["outbounds"] = customOutbounds
        }
        if settings.fakeDNSEnabled && profile.kind != .custom {
            var pools: [[String: Any]] = [["ipPool": "198.18.0.0/15", "poolSize": 65535]]
            if settings.ipv6Enabled { pools.append(["ipPool": "fc00::/18", "poolSize": 65535]) }
            root["fakedns"] = pools
        }
        if settings.localProxyEnabled, (1...65535).contains(settings.socksPort) {
            var proxySettings: [String: Any] = ["auth": "noauth", "udp": true]
            if !settings.socksUsername.isEmpty {
                proxySettings["auth"] = "password"
                proxySettings["accounts"] = [["user": settings.socksUsername, "pass": settings.socksPassword]]
            }
            var inbounds = (root["inbounds"] as? [[String: Any]] ?? []).filter { $0["tag"] as? String != "kindly-socks" }
            inbounds.append(["tag": "kindly-socks", "listen": "127.0.0.1", "port": settings.socksPort,
                             "protocol": "socks", "settings": proxySettings])
            root["inbounds"] = inbounds
        }
        guard let data = try? JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys]) else {
            return "{}"
        }
        return String(data: data, encoding: .utf8) ?? "{}"
    }

    static func compose(profiles: [VPNProfile], mode: ProfileComposition.Mode, settings: AppSettings) -> String? {
        guard profiles.count >= 2, profiles.allSatisfy({ $0.kind != .custom && !$0.isTURN && $0.connectionValidationError == nil }),
              let first = profiles.first,
              var root = try? JSONSerialization.jsonObject(with: Data(build(profile: first, settings: settings).utf8)) as? [String: Any] else { return nil }
        var members = profiles.map { proxyOutbound($0, settings) }
        for index in members.indices { members[index]["tag"] = mode == .chain && index == 0 ? "proxy" : "kindly-member-\(index)" }
        var routing = root["routing"] as? [String: Any] ?? [:]
        if mode == .chain {
            for index in members.indices.dropLast() {
                var stream = members[index]["streamSettings"] as? [String: Any] ?? [:]
                var sockopt = stream["sockopt"] as? [String: Any] ?? [:]
                sockopt["dialerProxy"] = members[index + 1]["tag"]
                stream["sockopt"] = sockopt; members[index]["streamSettings"] = stream
            }
        } else {
            members.insert(["tag": "proxy", "protocol": "loopback", "settings": ["inboundTag": "kindly-policy"]], at: 0)
            var rules = routing["rules"] as? [[String: Any]] ?? []
            rules.insert(["type": "field", "inboundTag": ["kindly-policy"], "balancerTag": "kindly-group"], at: 0)
            routing["rules"] = rules
            routing["balancers"] = [["tag": "kindly-group", "selector": ["kindly-member-"], "strategy": ["type": mode.rawValue]]]
            if mode == .leastPing {
                root["observatory"] = ["subjectSelector": ["kindly-member-"], "probeURL": settings.connectivityTestURL,
                                       "probeInterval": "1m", "enableConcurrency": true]
            }
        }
        var auxiliaries = (root["outbounds"] as? [[String: Any]] ?? []).filter { $0["tag"] as? String != "proxy" }
        if profiles.contains(where: \.packetFragmentation), !auxiliaries.contains(where: { $0["tag"] as? String == "fragment" }),
           let fragment = (outbounds(profiles.first(where: \.packetFragmentation)!, settings) as? [[String: Any]])?.first(where: { $0["tag"] as? String == "fragment" }) {
            auxiliaries.append(fragment)
        }
        root["outbounds"] = members + auxiliaries; root["routing"] = routing
        guard let data = try? JSONSerialization.data(withJSONObject: root, options: [.sortedKeys, .prettyPrinted]) else { return nil }
        return String(decoding: data, as: UTF8.self)
    }

    private static func dns(_ settings: AppSettings) -> [String: Any] {
        var servers: [Any] = []
        if settings.fakeDNSEnabled { servers.append("fakedns") }
        if !settings.remoteDNS.isEmpty {
            servers.append(settings.remoteDNS)
        }
        if !settings.directDNS.isEmpty, settings.routingMode == .rules,
           !settings.customDirectDomains.isEmpty || settings.bypassChina {
            var domains = settings.customDirectDomains
            if settings.bypassChina { domains.append("geosite:cn") }
            servers.insert(["address": settings.directDNS, "domains": domains, "skipFallback": true, "tag": "kindly-dns-direct"], at: 0)
        }
        // IP DNS through TURN/DNSTT must use a stream rather than relying on
        // an optional UDP relay. NetworkExtension's own DNS addresses stay IPs.
        servers.append(contentsOf: settings.vpnDNS.map { address -> String in
            guard !address.contains("/"), SplitTunnelAddress.isIP(address) else { return address }
            return "tcp://" + (address.contains(":") ? "[\(address)]" : address) + ":53"
        })
        return [
            "queryStrategy": settings.ipv6Enabled ? "UseIP" : "UseIPv4",
            "tag": "kindly-dns-query",
            "hosts": [
                "dns.google": ["8.8.8.8", "8.8.4.4"],
                "cloudflare-dns.com": ["1.1.1.1", "1.0.0.1"],
            ],
            "servers": servers,
        ]
    }

    private static func outbounds(_ profile: VPNProfile, _ appSettings: AppSettings) -> [Any] {
        var values: [Any] = [proxyOutbound(profile, appSettings)]
        if appSettings.packetFragmentation || profile.packetFragmentation {
            values.append([
                "tag": "fragment",
                "protocol": "freedom",
                "settings": [
                    "domainStrategy": "AsIs",
                    "fragment": [
                        "packets": appSettings.fragmentPackets,
                        "length": appSettings.fragmentLength,
                        "interval": appSettings.fragmentInterval,
                    ],
                ],
            ])
        }
        values.append([
            "tag": "direct",
            "protocol": "freedom",
            "settings": ["domainStrategy": appSettings.ipv6Enabled ? "UseIP" : "UseIPv4"],
        ])
        values.append([
            "tag": "block",
            "protocol": "blackhole",
            "settings": ["response": ["type": "http"]],
        ])
        values.append(["tag": "kindly-dns", "protocol": "dns", "settings": [:]])
        return values
    }

    private static func proxyOutbound(_ profile: VPNProfile, _ appSettings: AppSettings) -> [String: Any] {
        if profile.kind == .custom,
           let data = profile.rawOutboundJSON.data(using: .utf8),
           var value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            value["tag"] = "proxy"
            return value
        }

        var outbound: [String: Any] = [
            "tag": "proxy",
            "protocol": xrayProtocol(profile.kind),
            "settings": protocolSettings(profile),
        ]
        if profile.id == ManagedDNSSettings.builtInProfileID {
            // This SOCKS endpoint accepts literal targets. Resolve domain-only
            // requests with our tunneled DNS after routing; packet IPs stay intact.
            outbound["targetStrategy"] = appSettings.ipv6Enabled ? "ForceIP" : "ForceIPv4"
        }
        if supportsStreamSettings(profile.kind) {
            var stream = streamSettings(profile)
            if (appSettings.packetFragmentation || profile.packetFragmentation) &&
                ![.xhttp, .quic].contains(profile.transport) {
                stream["sockopt"] = ["dialerProxy": "fragment", "tcpNoDelay": true]
            }
            outbound["streamSettings"] = stream
        }
        let mux = (appSettings.muxEnabled || profile.muxEnabled) && supportsMux(profile)
        outbound["mux"] = ["enabled": mux, "concurrency": mux && profile.flow.isEmpty ? appSettings.muxConcurrency : -1,
                            "xudpConcurrency": 16, "xudpProxyUDP443": "reject"]
        return outbound
    }

    private static func xrayProtocol(_ kind: ProxyKind) -> String {
        switch kind {
        case .shadowsocks: return "shadowsocks"
        case .socks: return "socks"
        case .custom: return "freedom"
        default: return kind.rawValue
        }
    }

    private static func protocolSettings(_ profile: VPNProfile) -> [String: Any] {
        switch profile.kind {
        case .vless:
            var user: [String: Any] = ["id": profile.credential, "encryption": profile.encryption]
            if !profile.flow.isEmpty { user["flow"] = profile.flow }
            return ["vnext": [["address": profile.address, "port": profile.port, "users": [user]]]]
        case .vmess:
            return ["vnext": [[
                "address": profile.address,
                "port": profile.port,
                "users": [["id": profile.credential, "alterId": 0, "security": profile.encryption]],
            ]]]
        case .shadowsocks:
            return ["servers": [[
                "address": profile.address,
                "port": profile.port,
                "method": profile.shadowsocksMethod,
                "password": profile.shadowsocksPassword,
            ]]]
        case .trojan:
            return ["servers": [["address": profile.address, "port": profile.port, "password": profile.credential]]]
        case .wireguard:
            var peer: [String: Any] = [
                "publicKey": profile.wireguardPeerPublicKey,
                "allowedIPs": ["0.0.0.0/0", "::/0"],
                "endpoint": profile.wireguardEndpoint.isEmpty ? "\(profile.address.contains(":") ? "[\(profile.address)]" : profile.address):\(profile.port)" : profile.wireguardEndpoint,
            ]
            if !profile.wireguardPreSharedKey.isEmpty { peer["preSharedKey"] = profile.wireguardPreSharedKey }
            var result: [String: Any] = [
                "secretKey": profile.wireguardPrivateKey,
                "address": profile.wireguardAddresses,
                "peers": [peer],
                "mtu": profile.wireguardMTU,
                "domainStrategy": "ForceIP",
            ]
            if let reserved = reservedBytes(profile.wireguardReserved) { result["reserved"] = reserved }
            return result
        case .socks, .http:
            var server: [String: Any] = ["address": profile.address, "port": profile.port]
            let credentials = profile.credential.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false).map(String.init)
            if credentials.count == 2 {
                server["users"] = [["user": credentials[0], "pass": credentials[1]]]
            }
            return ["servers": [server]]
        case .custom:
            return [:]
        }
    }

    private static func streamSettings(_ profile: VPNProfile) -> [String: Any] {
        var value: [String: Any] = ["network": networkName(profile.transport)]
        switch profile.transport {
        case .ws:
            var ws: [String: Any] = ["path": profile.path.isEmpty ? "/" : profile.path]
            if !profile.host.isEmpty { ws["headers"] = ["Host": profile.host] }
            value["wsSettings"] = ws
        case .grpc:
            value["grpcSettings"] = ["serviceName": profile.grpcServiceName ?? profile.path,
                                      "authority": profile.grpcAuthority ?? profile.host,
                                      "multiMode": profile.transportMode == "multi",
                                      "idle_timeout": 60, "health_check_timeout": 20]
        case .xhttp:
            var xhttp: [String: Any] = [
                "path": profile.path.isEmpty ? "/" : profile.path,
                "host": profile.host.isEmpty ? (profile.sni.isEmpty ? profile.address : profile.sni) : profile.host,
                "mode": profile.transportMode ?? "auto",
            ]
            if let raw = profile.xhttpExtra, let data = raw.data(using: .utf8),
               let extra = try? JSONSerialization.jsonObject(with: data) { xhttp["extra"] = extra }
            value["xhttpSettings"] = xhttp
        case .httpUpgrade:
            value["httpupgradeSettings"] = ["path": profile.path, "host": profile.host]
        case .h2:
            value["httpSettings"] = ["path": profile.path, "host": stringList(profile.host)]
        case .kcp:
            var kcp: [String: Any] = [:]
            kcp["mtu"] = profile.kcpMTU; kcp["tti"] = profile.kcpTTI
            value["kcpSettings"] = kcp
            var masks = [[String: Any]]()
            if !profile.headerType.isEmpty && profile.headerType != "none" {
                masks.append(["type": "mkcp-legacy", "settings": [
                    "header": profile.headerType == "wechat-video" ? "wechat" : profile.headerType,
                    "value": profile.host,
                ]])
            }
            masks.append(["type": "mkcp-legacy", "settings": profile.seed.isEmpty ? [:] : ["value": profile.seed]])
            value["finalmask"] = ["udp": masks]
        case .tcp:
            if profile.headerType == "http" {
                let paths = stringList(profile.path)
                value["tcpSettings"] = ["header": ["type": "http", "request": [
                    "path": paths.isEmpty ? ["/"] : paths, "headers": ["Host": stringList(profile.host)],
                ]]]
            }
        case .quic:
            value["quicSettings"] = ["security": "none", "key": "", "header": ["type": profile.headerType]]
        }
        if let raw = profile.finalMask, let data = raw.data(using: .utf8),
           let mask = try? JSONSerialization.jsonObject(with: data) as? [String: Any] { value["finalmask"] = mask }

        let serverName = profile.sni.isEmpty
            ? ((profile.transport == .grpc ? profile.grpcAuthority : nil) ?? stringList(profile.host).first ?? profile.address)
            : profile.sni
        switch profile.security {
        case .none:
            value["security"] = "none"
        case .tls, .xtls:
            value["security"] = "tls"
            var tls: [String: Any] = [
                "serverName": serverName,
                "allowInsecure": profile.allowInsecure && (profile.pinnedCertificateSHA256 ?? "").isEmpty,
                "fingerprint": profile.fingerprint,
            ]
            if let alpn = profile.alpnValues { tls["alpn"] = alpn }
            if let pin = profile.pinnedCertificateSHA256, !pin.isEmpty { tls["pinnedPeerCertSha256"] = pin }
            tls["echConfigList"] = profile.echConfigList
            tls["verifyPeerCertByName"] = profile.verifyPeerCertByName
            value["tlsSettings"] = tls
        case .reality:
            value["security"] = "reality"
            var reality: [String: Any] = [
                "serverName": serverName,
                "fingerprint": profile.fingerprint,
                "publicKey": profile.publicKey,
                "shortId": profile.shortId,
                "spiderX": profile.spiderX,
            ]
            reality["mldsa65Verify"] = profile.mldsa65Verify
            value["realitySettings"] = reality
        }
        return value
    }

    private static func routing(_ settings: AppSettings) -> [String: Any] {
        var rules: [[String: Any]] = [
            ["type": "field", "inboundTag": ["in_proxy", "kindly-socks"], "port": "53", "outboundTag": "kindly-dns"],
            ["type": "field", "inboundTag": ["kindly-dns-direct"], "outboundTag": "direct"],
            ["type": "field", "inboundTag": ["kindly-dns-query"], "outboundTag": settings.routingMode == .direct ? "direct" : "proxy"],
        ]
        if !settings.ipv6Enabled {
            rules.append(["type": "field", "ip": ["::/0"], "outboundTag": "block"])
        }
        if settings.routingMode == .rules {
            for rule in settings.customRoutingRules ?? [] where rule.enabled && rule.isValid {
                var value: [String: Any] = ["type": "field", "outboundTag": rule.outbound]
                if !rule.domains.isEmpty { value["domain"] = rule.domains }
                if !rule.ips.isEmpty { value["ip"] = rule.ips }
                if !rule.port.isEmpty { value["port"] = rule.port }
                if !rule.network.isEmpty { value["network"] = rule.network }
                if !rule.protocols.isEmpty { value["protocol"] = rule.protocols }
                rules.append(value)
            }
        }
        if !settings.customBlockedDomains.isEmpty {
            rules.append(["type": "field", "outboundTag": "block", "domain": settings.customBlockedDomains])
        }
        if settings.blockAds {
            rules.append(["type": "field", "outboundTag": "block", "domain": ["geosite:category-ads-all"]])
        }
        if settings.routingMode == .direct {
            rules.append(["type": "field", "outboundTag": "direct", "network": "tcp,udp"])
        } else {
            if settings.routingMode == .rules, !settings.customDirectDomains.isEmpty {
                rules.append(["type": "field", "outboundTag": "direct", "domain": settings.customDirectDomains])
            }
            if settings.routingMode == .rules, settings.bypassChina {
                rules.append(["type": "field", "outboundTag": "direct", "domain": ["geosite:cn"]])
                rules.append(["type": "field", "outboundTag": "direct", "ip": ["geoip:cn"]])
            }
            if settings.bypassLocalNetwork {
                rules.append([
                    "type": "field", "outboundTag": "direct",
                    "ip": ["geoip:private", "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"],
                ])
            }
            rules.append(["type": "field", "outboundTag": "proxy", "network": "tcp,udp"])
        }
        return ["domainStrategy": settings.domainStrategy.rawValue, "domainMatcher": "hybrid", "rules": rules]
    }

    private static func supportsStreamSettings(_ kind: ProxyKind) -> Bool {
        ![.wireguard, .custom].contains(kind)
    }



    private static func supportsMux(_ profile: VPNProfile) -> Bool {
        [.vless, .vmess].contains(profile.kind) &&
            ![.xhttp, .quic].contains(profile.transport)
    }

    private static func networkName(_ kind: TransportKind) -> String {
        switch kind {
        case .h2: return "http"
        case .httpUpgrade: return "httpupgrade"
        default: return kind.rawValue
        }
    }

    private static func reservedBytes(_ raw: String) -> [Int]? {
        let values = raw.components(separatedBy: CharacterSet(charactersIn: ", "))
            .compactMap(Int.init)
            .filter { (0...255).contains($0) }
        return values.count == 3 ? values : nil
    }

    private static func stringList(_ raw: String) -> [String] {
        raw.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }
}

private extension VPNProfile {
    var alpnValues: [String]? {
        let values = (alpn ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        return values.isEmpty ? nil : values
    }
}
