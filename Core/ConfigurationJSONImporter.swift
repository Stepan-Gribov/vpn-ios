import Foundation

enum ConfigurationJSONImporter {
    struct ImportResult {
        let configuration: SimpleConfiguration
        let includesResolver: Bool
    }

    /// Import connection fields only; keep the row identity and local network preferences.
    static func apply(_ text: String, to original: SimpleConfiguration) throws -> ImportResult {
        guard text.utf8.count <= 65_536 else {
            throw ConfigurationError("JSON is too large. The maximum size is 64 KB.")
        }
        let root: [String: Any]
        do {
            guard let object = try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] else {
                throw ConfigurationError("Copy a single JSON object containing your settings.")
            }
            root = object
        } catch let error as ConfigurationError { throw error }
        catch { throw ConfigurationError("The clipboard does not contain valid JSON. Copy the entire configuration.") }

        let top = Fields(root)
        if let mode = try top.string(["mode"]) {
            guard let importedMode = TunnelMode(rawValue: mode.lowercased()) else {
                throw ConfigurationError("The mode field must be amnezia, turn or dns.")
            }
            guard importedMode == original.mode else {
                throw ConfigurationError("These settings are for \(importedMode.title). Open that mode and paste the JSON there.")
            }
        }

        var result = original
        var includesResolver = false
        switch original.mode {
        case .amnezia:
            result.amneziaKey = try top.string(["key", "amnezia_key", "amneziaKey"], required: true)!
        case .turn:
            result.callLink = try top.string(["call_link", "callLink", "vk_link"], required: true)!
            result.server = try top.string(["server", "peer_addr"], required: true)!
            result.vlessID = try top.string(["vless_id", "vlessID", "uuid"], required: true)!
            // An omitted key describes a server without the optional wrapping layer.
            result.wrapKey = try top.string(["wrap_key", "wrapKey"]) ?? ""
        case .dns:
            let nested = root["dns"] ?? root["managed_dns"]
            if let nested, !(nested is [String: Any]) {
                throw ConfigurationError("The dns field must contain a JSON object.")
            }
            let fields = Fields(nested as? [String: Any] ?? root)
            result.dns.domain = try fields.string(["domain"], required: true)!
            result.dns.publicKey = try fields.string(["public_key", "publicKey"], required: true)!
            result.dns.tunnelType = (try fields.string(["tunnel_type", "tunnelType"]) ?? "socks5").lowercased()
            if let resolver = try fields.string(["resolver"]) {
                result.dns.resolver = resolver
                includesResolver = true
            }
            result.dns.sshUsername = try fields.string(["ssh_username", "sshUsername"]) ?? ""
            result.dns.sshPassword = try fields.string(["ssh_password", "sshPassword"], trim: false) ?? ""
            result.dns.sshPrivateKey = try fields.string(["ssh_private_key", "sshPrivateKey"], trim: false) ?? ""
            result.dns.sshHostKey = try fields.string(["ssh_host_key", "sshHostKey"]) ?? ""
        }
        return ImportResult(configuration: try result.validated(forConnection: true), includesResolver: includesResolver)
    }

    private struct Fields {
        let values: [String: Any]
        init(_ values: [String: Any]) { self.values = values }

        func string(_ keys: [String], required: Bool = false, trim: Bool = true) throws -> String? {
            var found: String?
            for key in keys where values[key] != nil {
                guard let raw = values[key] as? String else {
                    throw ConfigurationError("The \(key) field must be a string.")
                }
                let value = trim ? raw.trimmingCharacters(in: .whitespacesAndNewlines) : raw
                if let found, found != value {
                    throw ConfigurationError("JSON contains conflicting values for the field \(keys[0]).")
                }
                found = value
            }
            if required && (found?.isEmpty ?? true) {
                throw ConfigurationError("JSON is missing the field \(keys[0]).")
            }
            return found
        }
    }
}
