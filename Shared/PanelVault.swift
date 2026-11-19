import Foundation
import CryptoKit
import Security
import Darwin

/// One authenticated encrypted transaction contains identity, tokens, assigned
/// profiles, both split lists, settings and revisions. No panel identity is portable.
final class PanelVault: @unchecked Sendable {
    static let shared = PanelVault()
    private let mutex = NSLock()
    private let overrideDirectory: URL?
    private let testKey: Data?
    private var cached: PanelVaultState?
    private var cachedStamp = ""
    private var accessStamp = ""
    private var accessRecords: [Data: PanelAccessIndex.Record] = [:]
    private var missingAccess = Set<Data>()

    init(directory: URL? = nil, key: Data? = nil) { overrideDirectory = directory; testKey = key }
    private var directory: URL {
        get throws {
            guard let result = overrideDirectory ?? AppGroup.containerURL else { throw PanelFailure("Secure subscription storage is unavailable.") }
            return result
        }
    }
    private func locked<T>(write: Bool, _ body: (URL) throws -> T) throws -> T {
        mutex.lock(); defer { mutex.unlock() }
        let directory = try directory
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let fd = open(directory.appendingPathComponent("panel-state.lock").path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR)
        guard fd >= 0 else { throw PanelFailure("Subscription storage could not be locked.") }
        defer { close(fd) }
        guard flock(fd, write ? LOCK_EX : LOCK_SH) == 0 else { throw PanelFailure("Subscription storage is busy.") }
        defer { flock(fd, LOCK_UN) }
        return try body(directory.appendingPathComponent("panel-state.enc"))
    }
    private func key(create: Bool) throws -> SymmetricKey {
        if let testKey { return SymmetricKey(data: testKey) }
        guard let group = Bundle.main.object(forInfoDictionaryKey: "PanelKeychainAccessGroup") as? String,
              !group.isEmpty, !group.contains("$(") else { throw PanelFailure("Shared Keychain signing is not configured.") }
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "TnDtun.panel.v1", kSecAttrAccount as String: "state-key",
            kSecAttrAccessGroup as String: group, kSecUseDataProtectionKeychain as String: true]
        var lookup = query; lookup[kSecReturnData as String] = true; lookup[kSecMatchLimit as String] = kSecMatchLimitOne
        var output: CFTypeRef?
        let result = SecItemCopyMatching(lookup as CFDictionary, &output)
        if result == errSecSuccess, let data = output as? Data, data.count == 32 { return SymmetricKey(data: data) }
        guard result == errSecItemNotFound && create else { throw PanelFailure("Unlock this device to access the subscription's secure storage.") }
        let key = SymmetricKey(size: .bits256)
        var insertion = query
        insertion[kSecValueData as String] = key.withUnsafeBytes { Data($0) }
        insertion[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let added = SecItemAdd(insertion as CFDictionary, nil)
        if added == errSecDuplicateItem { return try self.key(create: false) }
        guard added == errSecSuccess else { throw PanelFailure("Subscription credentials could not be saved in Keychain.") }
        return key
    }
    private func stamp(_ url: URL) -> String {
        var metadata = stat()
        guard lstat(url.path, &metadata) == 0 else { return "missing" }
        return "\(metadata.st_ino):\(metadata.st_size):\(metadata.st_mtimespec.tv_sec):\(metadata.st_mtimespec.tv_nsec)"
    }
    private func read(_ url: URL) throws -> PanelVaultState {
        let stamp = stamp(url)
        if let cached, cachedStamp == stamp { return cached }
        guard FileManager.default.fileExists(atPath: url.path) else { return PanelVaultState() }
        do {
            let bytes = try Data(contentsOf: url)
            guard bytes.count <= PanelAccessIndex.maximumFileSize else { throw PanelFailure("Subscription storage is too large.") }
            let clear = try PanelAccessIndex.open(bytes, key: key(create: false))
            let state = try JSONDecoder().decode(PanelVaultState.self, from: clear)
            cached = state; cachedStamp = stamp
            return state
        } catch let error as PanelFailure { throw error }
        catch { throw PanelFailure("Subscription storage could not be verified. Existing data was retained.") }
    }
    func snapshot() throws -> PanelVaultState { try locked(write: false) { try read($0) } }
    /// Manual-profile persistence uses the same lock as subscription acceptance,
    /// so a concurrent import cannot acquire a managed profile's identifier.
    func withManualWrite<T>(_ action: (PanelVaultState) throws -> T) throws -> T {
        try locked(write: true) { try action(read($0)) }
    }
    @discardableResult func transaction<T>(_ change: (inout PanelVaultState) throws -> T) throws -> T {
        try locked(write: true) { url in
            var state = try read(url)
            let value = try change(&state)
            let clear = try JSONEncoder().encode(state)
            guard clear.count <= 80 * 1024 * 1024 else { throw PanelFailure("Subscription storage is too large.") }
            let bytes = try PanelAccessIndex.seal(state, clear: clear, key: key(create: true))
            try bytes.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
            chmod(url.path, S_IRUSR | S_IWUSR)
            var file = url; var resources = URLResourceValues(); resources.isExcludedFromBackup = true
            try? file.setResourceValues(resources)
            cached = state; cachedStamp = stamp(url)
            return value
        }
    }
    func permits(_ grant: PanelAccessGrant, now: Int64) throws -> Bool {
        try locked(write: false) { url in
            guard FileManager.default.fileExists(atPath: url.path) else { return false }
            let currentStamp = stamp(url), lookup = PanelAccessIndex.lookupKey(grant)
            if accessStamp != currentStamp { accessStamp = currentStamp; accessRecords = [:]; missingAccess = [] }
            if let record = accessRecords[lookup] { return record.permits(grant, now: now) }
            if missingAccess.contains(lookup) { return false }
            do {
                guard let record = try PanelAccessIndex.lookup(grant, at: url, key: { try key(create: false) }) else {
                    missingAccess.insert(lookup); return false
                }
                accessRecords[lookup] = record
                return record.permits(grant, now: now)
            } catch PanelAccessIndex.Format.legacy { return try read(url).permits(grant, now: now) }
            catch let error as PanelFailure { throw error }
            catch { throw PanelFailure("Subscription access could not be verified. Open Subscription to review it.") }
        }
    }
    func installationID() throws -> String {
        if let existing = try? snapshot().installationID, !existing.isEmpty { return existing }
        return try transaction { state in
            if state.installationID.isEmpty { state.installationID = UUID().uuidString.lowercased() }
            return state.installationID
        }
    }
    /// The lease is held throughout await/retries/native cleanup. Extension code
    /// has no synchronizer, but a second app process cannot issue a parallel request.
    func requestLease() throws -> PanelRequestLease {
        try PanelRequestLease(url: directory.appendingPathComponent("panel-request.lock"))
    }
}

final class PanelRequestLease: @unchecked Sendable {
    private var fd: Int32
    init(url: URL) throws {
        fd = open(url.path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR)
        guard fd >= 0 else { throw PanelFailure("Subscription request storage is unavailable.") }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else {
            close(fd); fd = -1
            throw PanelFailure("Another subscription operation is running. Wait for it to finish.")
        }
    }
    deinit { if fd >= 0 { flock(fd, LOCK_UN); close(fd) } }
}

enum PanelAccess {
    static func require(_ grant: PanelAccessGrant?, vault: PanelVault = .shared, now: Int64 = Int64(Date().timeIntervalSince1970)) throws {
        guard let grant else { return }
        // The latest authenticated index owns expiry (including an explicitly
        // signed extension of access). Storage failure still denies admission.
        guard try vault.permits(grant, now: now) else {
            throw PanelFailure("This managed profile is expired, revoked, removed or has changed. Open Subscription to review it.")
        }
    }
}
