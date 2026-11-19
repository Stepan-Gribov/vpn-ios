import Foundation

extension TURNSettings {
    var isConfigured: Bool { isConfigured(hasMAXToken: TurnSecretStore.loadMAXToken() != nil) }
}

enum TurnSecretStore {
    private static let filename = "max-token"

    static func saveMAXToken(_ token: String?) {
        guard let directory = AppGroup.containerURL else { return }
        let url = directory.appendingPathComponent(filename, isDirectory: false)
        guard let token, !token.isEmpty else {
            try? FileManager.default.removeItem(at: url)
            return
        }
        let data = Data(token.utf8)
        try? data.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }

    static func loadMAXToken() -> String? {
        guard let directory = AppGroup.containerURL,
              let data = try? Data(contentsOf: directory.appendingPathComponent(filename)),
              let value = String(data: data, encoding: .utf8),
              !value.isEmpty else { return nil }
        return value
    }
}


/// App Group storage is readable by the packet extension, device-protected and excluded from backups.
/// Passwords and private keys stay out of UserDefaults. Explicit full-app
/// backup exports include them so profiles work on the destination device.
enum ManagedDNSStore {
    private static var url: URL? { AppGroup.containerURL?.appendingPathComponent("managed-dns.json") }
    static func load() throws -> ManagedDNSSettings {
        guard let url, FileManager.default.fileExists(atPath: url.path) else { return ManagedDNSSettings() }
        return try JSONDecoder().decode(ManagedDNSSettings.self, from: Data(contentsOf: url))
    }
    static func save(_ settings: ManagedDNSSettings) throws {
        guard var url else { throw ManagedDNSSettings.SetupError.invalid("App storage is unavailable.") }
        let data = try JSONEncoder().encode(settings.validated())
        try data.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        var values = URLResourceValues(); values.isExcludedFromBackup = true
        try? url.setResourceValues(values)
    }
    static func clear() throws {
        if let url, FileManager.default.fileExists(atPath: url.path) { try FileManager.default.removeItem(at: url) }
    }
}
