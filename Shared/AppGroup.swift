import Foundation
import Darwin

enum AppGroup {
    private static let fallbackID = "group.com.example.vpnapp"
    private static let legacyIDs: [String] = []

    static var id: String {
        guard let value = Bundle.main.object(forInfoDictionaryKey: "AppGroupIdentifier") as? String,
              !value.isEmpty else { return fallbackID }
        return value
    }

    static var tunnelBundleIdentifier: String {
        Bundle.main.object(forInfoDictionaryKey: "TunnelBundleIdentifier") as? String
            ?? "com.example.vpnapp.PacketTunnel"
    }

    static let profilesKey = "profiles.v1"
    static let subscriptionsKey = "subscriptions.v1"
    static let settingsKey = "settings.v1"
    static let activeProfileKey = "activeProfileId"
    static let activeConfigKey = "activeXrayConfig"
    static let turnSettingsKey = "turnSettings.v1"
    static let turnStatusKey = "turnRuntimeStatus.v1"
    static let recoveryStatusKey = "recoveryStatus.v1"
    static let recoveryActionKey = "recoveryAction.v1"
    static let logsKey = "runtimeLogs.v1"
    static let uploadedBytesKey = "uploadedBytes"
    static let downloadedBytesKey = "downloadedBytes"

    #if targetEnvironment(macCatalyst)
    static let defaults = MacSharedPreferences()
    #else
    static var defaults: UserDefaults {
        UserDefaults(suiteName: id) ?? .standard
    }
    #endif

    static func verifyAccess() throws {
        guard let directory = containerURL else {
            throw NSError(domain: "TnDtun.Storage", code: 1, userInfo: [NSLocalizedDescriptionKey: "Shared VPN data is inaccessible. Rebuild the app with valid signing."])
        }
        #if targetEnvironment(macCatalyst)
        do { try defaults.verifyAccess() }
        catch {
            throw NSError(domain: "TnDtun.Storage", code: 2, userInfo: [
                NSLocalizedDescriptionKey: "VPN settings could not be saved. \(error.localizedDescription)",
                NSUnderlyingErrorKey: error
            ])
        }
        #else
        // UserDefaults synchronization is not a filesystem access test. Verify
        // the shared files used by the iOS packet extension directly instead.
        try verifyFileAccess(in: directory)
        #endif
    }

    static func verifyFileAccess(in directory: URL) throws {
        let probe = directory.appendingPathComponent("storage-check-" + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: probe) }
        do {
            let expected = Data(UUID().uuidString.utf8)
            try expected.write(to: probe, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
            guard try Data(contentsOf: probe) == expected else { throw CocoaError(.fileReadCorruptFile) }
        } catch {
            RuntimeLog.write("Shared VPN file access failed: \(error.localizedDescription)")
            throw NSError(domain: "TnDtun.Storage", code: 2, userInfo: [
                NSLocalizedDescriptionKey: "VPN data could not be written to this device. \(error.localizedDescription)",
                NSUnderlyingErrorKey: error
            ])
        }
    }

    static var containerURL: URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: id)
    }

    static var activeConfigURL: URL? {
        containerURL?.appendingPathComponent("active-xray.json", isDirectory: false)
    }

    static func migrateLegacyDefaultsIfNeeded() {
        let target = defaults
        guard target.object(forKey: profilesKey) == nil else { return }

        let keys = [
            profilesKey, subscriptionsKey, settingsKey, activeProfileKey,
            activeConfigKey, turnSettingsKey, turnStatusKey, logsKey,
            uploadedBytesKey, downloadedBytesKey,
        ]
        for legacyID in legacyIDs where legacyID != id {
            guard let legacy = UserDefaults(suiteName: legacyID),
                  legacy.object(forKey: profilesKey) != nil else { continue }
            for key in keys {
                if let value = legacy.object(forKey: key) { target.set(value, forKey: key) }
            }
            target.synchronize()
            return
        }
    }
}

#if targetEnvironment(macCatalyst)
/// An atomic shared file avoids Catalyst CFPreferences detaching from cfprefsd.
/// All writes reload under an interprocess lock so app/provider updates merge.
final class MacSharedPreferences: @unchecked Sendable {
    private let mutex = NSLock()
    private var writeFailed = false
    private let directoryOverride: URL?

    init(directoryURL: URL? = nil) { directoryOverride = directoryURL }

    func verifyAccess() throws {
        let key = "storage-check-" + UUID().uuidString
        try access(write: true) { $0[key] = key }
        defer { removeObject(forKey: key) }
        guard try access(write: false, { $0[key] as? String }) == key else {
            throw CocoaError(.fileReadCorruptFile)
        }
    }

    private func access<T>(write: Bool, _ body: (inout [String: Any]) throws -> T) throws -> T {
        mutex.lock(); defer { mutex.unlock() }
        guard let directory = directoryOverride ?? AppGroup.containerURL else { throw CocoaError(.fileNoSuchFile) }
        let lockURL = directory.appendingPathComponent("shared-preferences.lock")
        let descriptor = Darwin.open(lockURL.path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR)
        guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        defer { Darwin.close(descriptor) }
        // Reads may repair a corrupt primary, so they also hold the exclusive
        // process lock. App and packet provider cannot race recovery/writes.
        guard flock(descriptor, LOCK_EX) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        defer { flock(descriptor, LOCK_UN) }
        let file = directory.appendingPathComponent("shared-preferences.plist")
        let backup = directory.appendingPathComponent("shared-preferences.backup.plist")
        var values: [String: Any] = [:]
        var originalData: Data?
        if FileManager.default.fileExists(atPath: file.path) {
            // Permission and I/O errors must remain errors; only malformed
            // contents can be restored from the last known good copy.
            let data = try Data(contentsOf: file)
            do {
                values = try Self.decode(data)
                originalData = data
            } catch {
                let recovered: [String: Any]
                if let saved = try? Data(contentsOf: backup), let decoded = try? Self.decode(saved) {
                    recovered = decoded
                } else { recovered = [:] }
                let quarantine = directory.appendingPathComponent("shared-preferences.corrupt-" + UUID().uuidString + ".plist")
                try data.write(to: quarantine, options: .atomic)
                let repaired = try Self.encode(recovered)
                try repaired.write(to: file, options: .atomic)
                values = recovered
                originalData = repaired
                NSLog("TnDtun restored unreadable shared preferences; original preserved as %@", quarantine.lastPathComponent)
            }
        }
        let result = try body(&values)
        if write {
            let data = try Self.encode(values)
            if let originalData { try originalData.write(to: backup, options: .atomic) }
            try data.write(to: file, options: .atomic)
            writeFailed = false
        }
        return result
    }

    private static func decode(_ data: Data) throws -> [String: Any] {
        guard let values = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
            throw CocoaError(.propertyListReadCorrupt)
        }
        return values
    }

    private static func encode(_ values: [String: Any]) throws -> Data {
        // XML avoids opaque binary-plist damage and is supported by old builds.
        // Validate before replacing either the primary or its recovery copy.
        let data = try PropertyListSerialization.data(fromPropertyList: values, format: .xml, options: 0)
        _ = try decode(data)
        return data
    }

    func object(forKey key: String) -> Any? { try? access(write: false) { $0[key] } }
    func string(forKey key: String) -> String? { object(forKey: key) as? String }
    func stringArray(forKey key: String) -> [String]? { object(forKey: key) as? [String] }
    func data(forKey key: String) -> Data? { object(forKey: key) as? Data }
    func bool(forKey key: String) -> Bool { (object(forKey: key) as? NSNumber)?.boolValue ?? false }
    func set(_ value: Any?, forKey key: String) {
        do { try access(write: true) { values in values[key] = value } }
        catch {
            mutex.lock(); writeFailed = true; mutex.unlock()
            NSLog("TnDtun shared preferences write failed for %@: %@", key, String(describing: error))
        }
    }
    func removeObject(forKey key: String) { set(nil, forKey: key) }
    func synchronize() -> Bool {
        (try? access(write: false) { _ in !writeFailed }) ?? false
    }
}
#endif
