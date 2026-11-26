import Foundation

var configuredDNSRecoveryURL: URL? {
    guard let value = Bundle.main.object(forInfoDictionaryKey: "VPNAppRecoveryURL") as? String,
          let url = URL(string: value), url.scheme == "https", url.host != nil,
          url.user == nil, url.password == nil, url.fragment == nil else { return nil }
    return url
}
import SwiftyXrayKit

/// Shared with the extension, protected on disk and excluded from backups.
/// Defaults holds only the switch, never room secrets or endpoint credentials.
enum RecoveryTransportStore {
    static let maximumBytes = 65_536
    static let readyTimeout: TimeInterval = 180
    static let legacyTelemostProfileID = "tndtun-debug-conference-pilot"
    private static let enabledKey = "recoveryTransports.enabled.v1"
    private static let failedKey = "recoveryTransports.failedRoute.v1"
    private static let dnsFailedKey = "dnsConnection.failedRoute.v1"
    static var startAfter: String { AppGroup.defaults.string(forKey: failedKey) ?? "" }
    static var dnsStartAfter: String { AppGroup.defaults.string(forKey: dnsFailedKey) ?? "" }

    static func recordFailure(profile: String?, dns: Bool = false) {
        guard let profile, profile.range(of: "^[a-zA-Z0-9_-]{1,40}$", options: .regularExpression) != nil else { return }
        AppGroup.defaults.set(profile, forKey: dns ? dnsFailedKey : failedKey)
    }
    private static var fileURL: URL? { AppGroup.containerURL?.appendingPathComponent("recovery-transports.json") }
    private static var dnsFileURL: URL? { AppGroup.containerURL?.appendingPathComponent("dns-connection.json") }
    static var dnsConfigured: Bool { dnsFileURL.map { FileManager.default.fileExists(atPath: $0.path) } ?? false }
    static var configured: Bool { fileURL.map { FileManager.default.fileExists(atPath: $0.path) } ?? false }
    static var enabled: Bool {
        get { AppGroup.defaults.bool(forKey: enabledKey) }
        set { AppGroup.defaults.set(newValue, forKey: enabledKey) }
    }

    static func save(_ data: Data) throws {
        try write(data, to: fileURL)
        AppGroup.defaults.removeObject(forKey: failedKey)
        enabled = false
    }

    private static func write(_ data: Data, to target: URL?) throws {
        guard data.count <= maximumBytes, let json = String(data: data, encoding: .utf8),
              KindlyTurnRuntime.validateRecovery(configurationJSON: json),
              let url = target else { throw StorageError.invalid }
        try writeProtected(data, to: url)
    }

    private static func writeProtected(_ data: Data, to target: URL) throws {
        var url = target
        try data.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try url.setResourceValues(values)
    }

    struct TelemostInput {
        let vlessID: UUID
        let recovery: Data

        static func normalized(_ data: Data, validate: (String) -> Bool = KindlyTurnRuntime.validateRecovery) throws -> Self {
            guard data.count <= maximumBytes,
                  let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  Set(root.keys) == ["vless_id", "recovery"],
                  let rawID = root["vless_id"] as? String,
                  let recovery = root["recovery"] as? [String: Any] else { throw StorageError.invalid }
            return try normalized(vlessID: rawID, recovery: recovery, validate: validate)
        }

        static func normalized(vlessID: String, recovery: Data) throws -> Self {
            guard recovery.count <= maximumBytes,
                  let value = try? JSONSerialization.jsonObject(with: recovery) as? [String: Any] else { throw StorageError.invalid }
            return try normalized(vlessID: vlessID, recovery: value, validate: KindlyTurnRuntime.validateRecovery)
        }

        private static func normalized(vlessID rawID: String, recovery input: [String: Any],
                                       validate: (String) -> Bool) throws -> Self {
            var recovery = input
            guard let vlessID = UUID(uuidString: rawID.trimmingCharacters(in: .whitespacesAndNewlines)),
                  let routes = recovery["profiles"] as? [[String: Any]], routes.count == 1,
                  routes[0]["type"] as? String == "conference",
                  let conference = routes[0]["conference"] as? [String: Any],
                  conference["provider"] as? String == "telemost",
                  let channel = conference["channel"] as? String,
                  ["vp8channel", "hiddify-kcp"].contains(channel) else { throw StorageError.invalid }
            // The profile owns its local listener and never inherits route rotation state.
            recovery["listen"] = "127.0.0.1:9000"
            recovery.removeValue(forKey: "start_after")
            let normalized = try JSONSerialization.data(withJSONObject: recovery, options: .sortedKeys)
            guard validate(String(decoding: normalized, as: UTF8.self)) else { throw StorageError.invalid }
            return Self(vlessID: vlessID, recovery: normalized)
        }
    }

    struct LegacyTelemostStore {
        let url: URL

        func load() throws -> TelemostInput? {
            do {
                return try TelemostInput.normalized(readConfiguration(from: url))
            } catch let error as CocoaError where error.code == .fileNoSuchFile || error.code == .fileReadNoSuchFile {
                return nil
            }
        }

        func save(_ data: Data) throws -> TelemostInput {
            let input = try TelemostInput.normalized(data)
            try writeProtected(data, to: url)
            return input
        }

        func remove() throws {
            if FileManager.default.fileExists(atPath: url.path) {
                try FileManager.default.removeItem(at: url)
            }
        }
    }

    static func legacyTelemostStore() throws -> LegacyTelemostStore {
        guard let directory = AppGroup.containerURL else { throw StorageError.missing }
        return LegacyTelemostStore(url: directory.appendingPathComponent("telemost-profile.json"))
    }

    private struct ActiveTelemost: Codable {
        let profileID: String
        let recovery: Data
    }

    private static var activeTelemostURL: URL? {
        AppGroup.containerURL?.appendingPathComponent("active-telemost.json")
    }

    static func prepareTelemost(profileID: String, recovery: Data?) throws {
        guard let url = activeTelemostURL else { throw StorageError.missing }
        if let recovery {
            let value = try JSONEncoder().encode(ActiveTelemost(profileID: profileID, recovery: recovery))
            try writeProtected(value, to: url)
        } else if FileManager.default.fileExists(atPath: url.path) {
            try FileManager.default.removeItem(at: url)
        }
    }

    static func loadTelemost(profileID: String) throws -> Data {
        guard let url = activeTelemostURL else { throw StorageError.missing }
        // The envelope includes the base64 encoding of the validated JSON.
        let data = try Data(contentsOf: url)
        guard data.count <= maximumBytes * 2 else { throw StorageError.invalid }
        let staged = try JSONDecoder().decode(ActiveTelemost.self, from: data)
        guard staged.profileID == profileID else { throw StorageError.missing }
        return staged.recovery
    }

    static func downloadDNS() async throws {
        try save(await fetchDNS())
    }

    static func refreshDNS() async throws {
        do {
            let data = try DNSConnection.normalized(await fetchDNS())
            try Task.checkCancellation()
            try write(data, to: dnsFileURL)
        } catch {
            if Task.isCancelled { throw CancellationError() }
            // Retain the last validated configuration for offline connections.
        }
    }

    static func loadDNS() throws -> Data {
        guard let url = dnsFileURL else { throw StorageError.missing }
        return try readConfiguration(from: url)
    }

    private static func fetchDNS() async throws -> Data {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 12
        configuration.timeoutIntervalForResource = 15
        configuration.httpShouldSetCookies = false
        configuration.httpCookieStorage = nil
        configuration.urlCache = nil
        let session = URLSession(configuration: configuration, delegate: DNSRecoveryDownloadDelegate(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        guard let url = configuredDNSRecoveryURL else { throw StorageError.unavailable }
        let (bytes, response) = try await session.bytes(from: url)
        guard let http = response as? HTTPURLResponse else { throw StorageError.invalid }
        if http.statusCode == 404 { throw StorageError.unavailable }
        guard http.statusCode == 200,
              http.mimeType == "application/json",
              http.expectedContentLength <= Int64(maximumBytes) else { throw StorageError.invalid }
        var data = Data()
        for try await byte in bytes {
            guard data.count < maximumBytes else { throw StorageError.invalid }
            data.append(byte)
        }
        try Task.checkCancellation()
        return data
    }

    static func load() throws -> Data {
        guard let url = fileURL else { throw StorageError.missing }
        return try readConfiguration(from: url)
    }

    static func readConfiguration(from url: URL) throws -> Data {
        let file = try FileHandle(forReadingFrom: url)
        defer { try? file.close() }
        var data = Data()
        while let part = try file.read(upToCount: min(8192, maximumBytes + 1 - data.count)), !part.isEmpty {
            data.append(part)
            guard data.count <= maximumBytes else { throw StorageError.invalid }
        }
        return data
    }

    static func clear() throws {
        if let url = fileURL, configured { try FileManager.default.removeItem(at: url) }
        enabled = false
    }

    enum StorageError: LocalizedError {
        case invalid, missing, unavailable
        var errorDescription: String? {
            switch self {
            case .invalid: return "Check the configuration file, keys and route support in this build."
            case .missing: return "Import a fallback route configuration."
            case .unavailable: return "DNS connectivity is currently unavailable. The saved configuration is unchanged."
            }
        }
    }
}

private final class DNSRecoveryDownloadDelegate: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}
