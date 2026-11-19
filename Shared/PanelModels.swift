import Foundation
import CryptoKit

struct PanelDNS: Codable, Equatable, Sendable {
    var domain: String
    var publicKey: String
    var resolver: String
    var sessionCount = 4
    var autoDetectResolver = true
    var savedResolvers: [String] = []
    var useWiFiResolver = false
    var wifiResolver = "8.8.8.8:53"
}

struct PanelTrust: Codable, Equatable, Sendable, CustomStringConvertible {
    var api: String
    var keyID: String
    var publicKey: String
    var dns: PanelDNS
    var description: String { "PanelTrust" }
    var sourceID: String { api + "#" + keyID + "#" + publicKey }
    func sameSource(_ other: Self) -> Bool { api == other.api && keyID == other.keyID && publicKey == other.publicKey }
}

struct PanelActivation: Sendable, CustomStringConvertible {
    var code: String
    var trust: PanelTrust
    var description: String { "PanelActivation" }
}

struct PanelManagedProfile: Codable, Equatable, Hashable {
    var subscriptionID: String
    var inboundID: String
    var nodeID: String
    var generation: Int64
    var title: String
    var location: String
    var credentialScope = "device"
    var credentialDigest: String
    var expiresAt: Int64?
}

struct PanelAssignedProfile: Codable, Equatable, CustomStringConvertible {
    var id: String
    var mode: String
    var generation: Int64
    var title: String
    var location: String
    var inboundID: String
    var nodeID: String
    var credentialScope: String
    var amneziaKey: String?
    var server: String?
    var callLink: String?
    var vlessID: String?
    var wrapKey: String?
    var description: String { "PanelAssignedProfile" }
    var credentialDigest: String {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        // Display names/locations do not rotate a working credential.
        let fields = ["mode": mode, "amnezia": amneziaKey ?? "", "server": server ?? "", "call": callLink ?? "",
                      "uuid": vlessID ?? "", "wrap": wrapKey ?? ""]
        return SHA256.hash(data: (try? encoder.encode(fields)) ?? Data()).map { String(format: "%02x", $0) }.joined()
    }
}

struct PanelSettings: Codable, Equatable {
    var autoCaptcha: Bool
    var autoRecovery: Bool
    var turnCheckInterval: Int
    var dnsServers: [String]
    var dnsTunnel: PanelDNS?
    var splitTunneling: SplitTunnelSettings
}

struct PanelPackage: Codable, Equatable, CustomStringConvertible {
    var revision: Int64
    var nonce: String
    var issuedAt: String
    var clientID: String
    var clientName: String
    var deviceID: String
    var status: String
    var expiresAt: Int64?
    var syncAfterSeconds: Int64
    var profiles: [PanelAssignedProfile]
    var settings: PanelSettings?
    var subscriptionCode: String? = nil
    var description: String { "PanelPackage" }
}

struct PanelSubscription: Codable, Equatable, Identifiable, CustomStringConvertible {
    var id: String
    var trust: PanelTrust
    var token: String
    var package: PanelPackage
    var lastSync: Int64
    var needsActivation = false
    var subscriptionCode: String? = nil
    var description: String { "PanelSubscription" }
    func accessAllowed(now: Int64) -> Bool { package.status == "active" && (package.expiresAt.map { now < $0 } ?? true) }
    func statusText(now: Int64) -> String {
        if package.status == "revoked" { return "Access revoked" }
        if !accessAllowed(now: now) { return "Access expired" }
        return needsActivation ? "Reactivate access" : "Access active"
    }
}

struct PanelAccessGrant: Codable, Equatable, Hashable {
    var subscriptionID: String
    var profileID: String
    var generation: Int64
    var credentialDigest: String
    var expiresAt: Int64?
}

struct PanelVaultState: Codable, Equatable {
    var installationID = ""
    var subscriptions: [PanelSubscription] = []
    var sourceEpochs: [String: Int] = [:]
    var activeSettingsOwner: String?
    var globalSettings: PanelSettings?
    var baselineSettings: PanelSettings?
    var settingsEpoch = ""
    var records: [PanelAssignedProfile] { subscriptions.flatMap { $0.package.profiles } }

    mutating func accept(_ package: PanelPackage, trust: PanelTrust, token: String, expectedEpoch: Int,
                         activation: Bool, manualIDs: Set<String>, baseline: PanelSettings, now: Int64) throws {
        guard sourceEpochs[trust.api, default: 0] == expectedEpoch else { throw PanelFailure("This subscription was removed while the request was running.") }
        let id = trust.api + "#" + package.deviceID
        let previous = subscriptions.first { $0.id == id }
        guard token.utf8.count <= 4096, !token.isEmpty, token.utf8.allSatisfy({ (33...126).contains($0) }),
              previous == nil || (previous!.package.clientID == package.clientID && package.revision >= previous!.package.revision &&
                                  (activation || previous!.trust.sameSource(trust))) else { throw PanelFailure("The accepted subscription changed. Activate it again.") }
        let occupied = manualIDs.union(subscriptions.filter { $0.id != id }.flatMap { $0.package.profiles.map(\.id) })
        guard !package.profiles.contains(where: { occupied.contains($0.id) }) else { throw PanelFailure("A profile ID is already used by another source.") }
        var stored = package
        if stored.settings == nil { stored.settings = previous?.package.settings }
        if baselineSettings == nil { baselineSettings = baseline }
        subscriptions.removeAll { $0.id == id }
        subscriptions.append(PanelSubscription(id: id, trust: trust, token: token, package: stored, lastSync: now, subscriptionCode: package.subscriptionCode ?? previous?.subscriptionCode))
        if activation || previous == nil || activeSettingsOwner == nil || activeSettingsOwner == id {
            activeSettingsOwner = id
            if let settings = package.settings { globalSettings = settings; settingsEpoch = UUID().uuidString }
        }
    }
    mutating func remove(_ id: String) {
        guard let removed = subscriptions.first(where: { $0.id == id }) else { return }
        sourceEpochs[removed.trust.api, default: 0] += 1
        subscriptions.removeAll { $0.id == id }
        if activeSettingsOwner == id {
            activeSettingsOwner = subscriptions.last?.id
            globalSettings = subscriptions.last?.package.settings ?? baselineSettings
            settingsEpoch = UUID().uuidString
        }
    }
    func permits(_ grant: PanelAccessGrant, now: Int64) -> Bool {
        guard let sub = subscriptions.first(where: { $0.id == grant.subscriptionID }), sub.accessAllowed(now: now),
              let row = sub.package.profiles.first(where: { $0.id == grant.profileID }),
              row.generation == grant.generation, row.credentialDigest == grant.credentialDigest else { return false }
        return true
    }
}
