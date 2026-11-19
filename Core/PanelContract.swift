import Foundation
import CryptoKit
import Security

enum PanelContract {
    static let envelopeLimit = 12 * 1024 * 1024
    static let payloadLimit = 8 * 1024 * 1024
    static func nonce() throws -> String {
        var bytes = [UInt8](repeating: 0, count: 24)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { throw PanelFailure("Secure random data is unavailable.") }
        return base64URL(Data(bytes))
    }
    static func base64URL(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
    static func decode64(_ raw: String, limit: Int) throws -> Data {
        guard raw.utf8.count <= limit * 4 / 3 + 4,
              raw.utf8.allSatisfy({ (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45 || $0 == 95 }) else {
            throw PanelFailure("Invalid package encoding.")
        }
        var text = raw.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        text += String(repeating: "=", count: (4 - text.count % 4) % 4)
        guard let data = Data(base64Encoded: text), data.count <= limit else { throw PanelFailure("Invalid package encoding.") }
        return data
    }
    static func normalizeCode(_ raw: String) throws -> String {
        let value = String(raw.filter { !$0.isWhitespace && $0 != "-" }).uppercased()
        let short = value.utf8.count == 4 && value.utf8.allSatisfy { (65...90).contains($0) }
        let legacy = value.utf8.count == 26 && value.utf8.allSatisfy { (65...90).contains($0) || (50...55).contains($0) }
        guard short || legacy else {
            throw PanelFailure("Enter a 4-letter activation code (A–Z) or an older 26-character code supplied by your administrator.")
        }; return value
    }
    // The add form accepts only short keys. Never truncate a pasted link or
    // legacy code into a different, potentially valid, four-letter key.
    static func subscriptionKeyInput(_ raw: String) throws -> String {
        guard raw.utf8.count <= 128 else { throw PanelFailure("Use 4 English letters (A–Z).") }
        let letters = raw.filter { !$0.isWhitespace && $0 != "-" }
        guard letters.utf8.count <= 4, letters.utf8.allSatisfy({ (65...90).contains($0) || (97...122).contains($0) }) else {
            throw PanelFailure("Use 4 English letters (A–Z).")
        }
        return letters.uppercased()
    }
    static func subscriptionKey(_ raw: String) throws -> String {
        let value = try subscriptionKeyInput(raw)
        guard value.utf8.count == 4 else { throw PanelFailure("Enter all 4 letters of your key.") }
        return value
    }
    static func api(_ raw: String) throws -> String {
        guard var u = URLComponents(string: raw), u.scheme == "https", let host = u.host, !host.isEmpty,
              u.user == nil, u.password == nil, u.query == nil, u.fragment == nil,
              ["/v1", "/v1/"].contains(u.percentEncodedPath), u.port.map({ (1...65535).contains($0) }) ?? true else {
            throw PanelFailure("The service must use an HTTPS address ending in /v1.")
        }
        u.host = host.lowercased(); u.path = "/v1"
        if u.port == 443 { u.port = nil }
        guard let value = u.url?.absoluteString else { throw PanelFailure("Invalid service address.") }; return value
    }
    static func trust(api: String, kid: String, key: String, dns: PanelDNS) throws -> PanelTrust {
        guard kid.range(of: "^[a-f0-9]{16}$", options: .regularExpression) != nil,
              try decode64(key, limit: 32).count == 32 else { throw PanelFailure("Invalid service signing key.") }
        return PanelTrust(api: try self.api(api), keyID: kid, publicKey: key, dns: try validatedDNS(dns))
    }
    static func bootstrap(_ data: Data) throws -> PanelTrust {
        let root = try PanelJSON.parse(data, limit: 16 * 1024)
        guard try root.field("api_version").integer == 1, try root.field("package_schema").integer == 1,
              try root.field("algorithm").text() == "Ed25519" else { throw PanelFailure("The bundled service configuration is unsupported.") }
        return try trust(api: root.field("api_base").text(2048), kid: root.field("key_id").text(),
                         key: root.field("public_key").text(), dns: dns(root.field("dns_transport")))
    }
    static func bundled() throws -> PanelTrust {
        guard let url = Bundle.main.url(forResource: "panel-bootstrap", withExtension: "json") else { throw PanelFailure("The bundled panel transport is missing. Reinstall TnDtun.") }
        return try bootstrap(Data(contentsOf: url))
    }
    static func activation(_ raw: String, bootstrap: PanelTrust) throws -> PanelActivation {
        guard raw.utf8.count <= 8192 else { throw PanelFailure("The activation code or link is too long.") }
        let raw = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard raw.lowercased().hasPrefix("tndtun:") else { return PanelActivation(code: try normalizeCode(raw), trust: bootstrap) }
        guard raw.utf8.count <= 8192, let u = URLComponents(string: raw), u.scheme?.lowercased() == "tndtun",
              u.host == "activate", u.user == nil, u.password == nil, u.port == nil, u.path.isEmpty, u.fragment == nil,
              let query = u.percentEncodedQuery else { throw PanelFailure("Invalid activation link.") }
        var fields: [String: String] = [:]
        for part in query.split(separator: "&", omittingEmptySubsequences: false) {
            let pair = part.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard pair.count == 2,
                  let name = String(pair[0]).replacingOccurrences(of: "+", with: " ").removingPercentEncoding,
                  let value = String(pair[1]).replacingOccurrences(of: "+", with: " ").removingPercentEncoding,
                  ["api", "code", "key", "kid"].contains(name), fields[name] == nil else { throw PanelFailure("Duplicate or unsupported activation-link field.") }
            fields[name] = value
        }
        guard fields.count == 4 else { throw PanelFailure("The activation link is incomplete.") }
        return try PanelActivation(code: normalizeCode(fields["code"]!), trust: trust(api: fields["api"]!, kid: fields["kid"]!, key: fields["key"]!, dns: bootstrap.dns))
    }
    static func uuid(_ value: PanelJSON) throws -> String {
        let text = try value.text()
        guard text.range(of: "^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$", options: .regularExpression) != nil else {
            throw PanelFailure("Invalid identifier in the service response.")
        }; return text
    }
    static func dns(_ value: PanelJSON) throws -> PanelDNS {
        let fields = try value.object
        if let type = fields["tunnelType"], try type.text() != "socks5" { throw PanelFailure("Unsupported panel DNS transport.") }
        return try validatedDNS(PanelDNS(domain: value.field("domain").text(253), publicKey: value.field("publicKey").text(),
            resolver: value.field("resolver").text(), sessionCount: Int(fields["sessionCount"].map { try $0.integer } ?? 4),
            autoDetectResolver: fields["autoDetectResolver"].map { try $0.boolean } ?? true,
            savedResolvers: fields["savedResolvers"].map { try stringList($0, maximum: 100) } ?? [],
            useWiFiResolver: fields["useWiFiResolver"].map { try $0.boolean } ?? false,
            wifiResolver: fields["wifiResolver"].map { try $0.text() } ?? "8.8.8.8:53"))
    }
    static func validatedDNS(_ value: PanelDNS) throws -> PanelDNS {
        var result = value
        result.domain = try SplitTunnelAddress.normalize(value.domain)
        guard !SplitTunnelAddress.isIP(result.domain), [1, 2, 4, 8].contains(value.sessionCount),
              value.publicKey.range(of: "^[0-9a-fA-F]{64}$", options: .regularExpression) != nil,
              value.savedResolvers.count <= 100 else { throw PanelFailure("Invalid panel DNS transport configuration.") }
        result.publicKey = value.publicKey.lowercased()
        result.resolver = try ManagedDNSSettings.normalizeResolver(value.resolver)
        result.wifiResolver = try ManagedDNSSettings.normalizeResolver(value.wifiResolver)
        result.savedResolvers = try value.savedResolvers.map(ManagedDNSSettings.normalizeResolver)
        return result
    }
    static func stringList(_ value: PanelJSON, maximum: Int) throws -> [String] {
        let list = try value.array
        guard list.count <= maximum else { throw PanelFailure("A service list is too large.") }
        return try list.map { try $0.text(2048) }
    }
    static func settings(_ value: PanelJSON) throws -> PanelSettings {
        guard try value.encoded().count <= 5 * 1024 * 1024 else { throw PanelFailure("Subscription settings are too large.") }
        let interval = try value.field("turnCheckInterval").integer
        guard (15...300).contains(interval) else { throw PanelFailure("Invalid background check interval.") }
        let rawServers = try stringList(value.field("dnsServers"), maximum: 100)
        guard !rawServers.isEmpty else { throw PanelFailure("The service DNS list is empty.") }
        let servers = try rawServers.map(ManagedDNSSettings.normalizeResolver).reduce(into: [String]()) { if !$0.contains($1) { $0.append($1) } }
        let tunnel = try value.field("dnsTunnel")
        let splitJSON = try value.field("splitTunneling")
        guard let mode = SplitTunnelMode(rawValue: try splitJSON.field("mode").text()) else { throw PanelFailure("Invalid split tunneling mode.") }
        func entries(_ name: String) throws -> [SplitTunnelEntry] {
            let list = try splitJSON.field(name).array
            guard list.count <= 20_000 else { throw PanelFailure("The address list is too large.") }
            return try list.map { item in
                let networks = try stringList(item.field("networks"), maximum: 100_000)
                return SplitTunnelEntry(address: try item.field("address").text(2048), networks: networks,
                    isNetworkGroup: try item.field("isNetworkGroup").boolean)
            }
        }
        var split = try SplitTunnelSettings(mode: mode, bypassEntries: entries("bypassEntries"), tunnelEntries: entries("tunnelEntries")).validated()
        if let push = try splitJSON.object["pushNotifications"] {
            guard Set(try push.object.keys) == ["apple", "google"] else { throw PanelFailure("Invalid push notification settings.") }
            split.pushNotifications = try PushNotificationSettings(apple: push.field("apple").boolean, google: push.field("google").boolean)
        }
        return try PanelSettings(autoCaptcha: value.field("autoCaptcha").boolean, autoRecovery: value.field("autoRecovery").boolean,
            turnCheckInterval: Int(interval), dnsServers: servers, dnsTunnel: tunnel.isNull ? nil : dns(tunnel), splitTunneling: split)
    }
    static func verify(_ envelope: Data, trust: PanelTrust, nonce: String, deviceID: String,
                       previous: PanelSubscription? = nil) throws -> PanelPackage {
        let outer = try PanelJSON.parse(envelope, limit: envelopeLimit)
        guard try outer.field("algorithm").text() == "Ed25519", try outer.field("key_id").text() == trust.keyID else { throw PanelFailure("The service used an untrusted signing key.") }
        let payload = try decode64(outer.field("payload").text(envelopeLimit), limit: payloadLimit)
        let signature = try decode64(outer.field("signature").text(), limit: 64)
        let key = try Curve25519.Signing.PublicKey(rawRepresentation: decode64(trust.publicKey, limit: 32))
        guard signature.count == 64, key.isValidSignature(signature, for: payload) else { throw PanelFailure("The package signature is invalid. Saved settings were retained.") }
        // The original bytes above are the only bytes authenticated. Parse later.
        let p = try PanelJSON.parse(payload, limit: payloadLimit)
        guard try p.field("format").text() == "TnDtun-package", try p.field("schema_version").integer == 1 else { throw PanelFailure("Update TnDtun to support this package format.") }
        guard try p.field("nonce").text() == nonce else { throw PanelFailure("The response belongs to another request.") }
        let device = try uuid(p.field("device_id")), client = try uuid(p.field("client_id"))
        guard device == deviceID, previous.map({ $0.package.clientID == client }) ?? true else { throw PanelFailure("The package belongs to another device or client.") }
        let revision = try p.field("revision").integer
        guard revision >= 0, revision >= (previous?.package.revision ?? 0) else { throw PanelFailure("The service returned an older revision.") }
        let status = try p.field("status").text()
        guard ["active", "revoked"].contains(status) else { throw PanelFailure("Unsupported access status.") }
        let expiry = try p.field("expires_at")
        let expiresAt: Int64? = try expiry.isNull ? nil : expiry.integer
        guard expiresAt.map({ $0 >= 0 && $0 <= Int64.max / 1000 }) ?? true else { throw PanelFailure("Invalid access expiry.") }
        let sync = try p.field("sync_after_seconds").integer
        guard (1...86400).contains(sync) else { throw PanelFailure("Invalid subscription interval.") }
        let issued = try p.field("issued_at").text()
        let date = ISO8601DateFormatter(); date.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let plain = ISO8601DateFormatter()
        guard date.date(from: issued) != nil || plain.date(from: issued) != nil else { throw PanelFailure("Invalid package issue date.") }
        let rawProfiles = try p.field("profiles").array
        guard rawProfiles.count <= 1000 else { throw PanelFailure("The service sent too many profiles.") }
        var ids = Set<String>()
        let profiles = try rawProfiles.map { row -> PanelAssignedProfile in
            let id = try uuid(row.field("id")), mode = try row.field("mode").text(), generation = try row.field("generation").integer
            guard ids.insert(id).inserted, ["amnezia", "turn"].contains(mode), generation >= 1 else { throw PanelFailure("Duplicate or unsupported assigned profile.") }
            let fields = try row.object
            let scope = try fields["credential_scope"].map { try $0.text() } ?? "device"
            guard ["device", "shared"].contains(scope) else { throw PanelFailure("Invalid credential scope.") }
            let profile = try PanelAssignedProfile(id: id, mode: mode, generation: generation, title: row.field("title").text(),
                location: row.field("location").text(), inboundID: row.field("inbound_id").text(), nodeID: row.field("node_id").text(), credentialScope: scope,
                amneziaKey: mode == "amnezia" ? row.field("amneziaKey").text(AmneziaImporter.maximumSize, lines: true) : nil,
                server: mode == "turn" ? row.field("server").text() : nil, callLink: mode == "turn" ? row.field("callLink").text(4096) : nil,
                vlessID: mode == "turn" ? row.field("vlessID").text() : nil, wrapKey: mode == "turn" ? row.field("wrapKey").text() : nil)
            guard !profile.title.trimmingCharacters(in: .whitespaces).isEmpty, !profile.inboundID.trimmingCharacters(in: .whitespaces).isEmpty,
                  !profile.nodeID.trimmingCharacters(in: .whitespaces).isEmpty else { throw PanelFailure("An assigned profile is incomplete.") }
            _ = try profile.configuration(subscriptionID: trust.api + "#" + device).validated(forConnection: true)
            return profile
        }
        guard status != "revoked" || profiles.isEmpty else { throw PanelFailure("A revoked package contains active profiles.") }
        let settings = try status == "active" ? self.settings(p.field("settings")) : nil
        if let legacyDNS = try p.object["bootstrap_dns"], try dns(legacyDNS) != settings?.dnsTunnel { throw PanelFailure("Contradictory panel DNS parameters.") }
        let code = try p.object["subscription_code"].flatMap { value in
            try value.isNull ? nil : normalizeCode(value.text(128))
        }
        return try PanelPackage(revision: revision, nonce: nonce, issuedAt: issued, clientID: client, clientName: p.field("client_name").text(100),
            deviceID: device, status: status, expiresAt: expiresAt, syncAfterSeconds: sync, profiles: profiles, settings: settings, subscriptionCode: code)
    }
}

extension PanelAssignedProfile {
    func configuration(subscriptionID: String, expiresAt: Int64? = nil) throws -> SimpleConfiguration {
        var result = SimpleConfiguration()
        result.id = id
        guard let mode = TunnelMode(rawValue: mode), mode != .dns else { throw PanelFailure("Unsupported assigned profile type.") }
        result.mode = mode; result.amneziaKey = amneziaKey
        result.server = server ?? ""; result.callLink = callLink ?? ""; result.vlessID = vlessID ?? ""; result.wrapKey = wrapKey ?? ""
        result.managed = PanelManagedProfile(subscriptionID: subscriptionID, inboundID: inboundID, nodeID: nodeID, generation: generation,
            title: title, location: location, credentialScope: credentialScope, credentialDigest: credentialDigest, expiresAt: expiresAt)
        return result
    }
}
