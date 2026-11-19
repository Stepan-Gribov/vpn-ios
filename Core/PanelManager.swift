import Foundation
import SwiftUI
import UIKit
import CryptoKit

enum SubscriptionAddition: Equatable {
    case idle, adding, added, failed(String)
}

/// Explicit user operations only. No startup, reachability or VPN event calls sync.
@MainActor
final class PanelManager: ObservableObject {
    @Published private(set) var subscriptions: [PanelSubscription] = []
    @Published private(set) var reconnectRecommended = UserDefaults.standard.bool(forKey: "panel.routingPending") {
        didSet { UserDefaults.standard.set(reconnectRecommended, forKey: "panel.routingPending") }
    }
    @Published private(set) var pendingCount = 0
    @Published private(set) var progress = ""
    @Published var error: String?
    @Published private(set) var activationText = ""
    @Published var showingSubscription = false
    @Published private(set) var addition: SubscriptionAddition = .idle
    private let store: SimpleStore
    private let clientOverride: PanelClient?
    private let activationTrust: PanelTrust?
    private weak var runtime: AppStore?
    private weak var vpn: VPNManager?
    private var tasks: [String: Task<Void, Never>] = [:]
    private var tail: Task<Void, Never>?
    private var current: Task<Void, Never>?
    private lazy var client: PanelClient = {
        if let clientOverride { return clientOverride }
        let url = store.manualFileURL
        let manager = self
        return PanelClient(vault: store.panelVault, exchange: PanelNativeExchange(readSystemDNS: { [weak manager] in
            await manager?.canReadSystemDNS() ?? false
        }, progress: { [weak manager] route in
            await manager?.showTransferProgress(route)
        }), currentManualIDs: { try SimpleStore.manualIDs(at: url) })
    }()
    init(store: SimpleStore, client: PanelClient? = nil, activationTrust: PanelTrust? = nil) {
        self.store = store; self.clientOverride = client; self.activationTrust = activationTrust; reload()
    }
    private func canReadSystemDNS() -> Bool { vpn?.tunnelIsActive == false }
    private func showTransferProgress(_ route: PanelTransferRoute) {
        guard current != nil, busy else { return }
        progress = route.message
    }
    func attach(runtime: AppStore, vpn: VPNManager) { self.runtime = runtime; self.vpn = vpn }
    var busy: Bool { pendingCount > 0 }
    func reload() { do { subscriptions = try store.panelVault.snapshot().subscriptions } catch { self.error = error.localizedDescription } }
    func updateActivationText(_ value: String) {
        guard value.utf8.count <= 8192 else { error = "The activation code or link is too long."; return }
        activationText = value
    }
    var isAddingSubscription: Bool { addition == .adding }
    var canAddSubscription: Bool { !busy && addition != .added && (try? PanelContract.subscriptionKey(activationText)) != nil }
    func prepareSubscriptionForm() {
        guard !isAddingSubscription else { return }
        addition = .idle
        activationText = (try? PanelContract.subscriptionKeyInput(activationText)) ?? ""
    }
    func updateSubscriptionKey(_ value: String) {
        guard !busy else { return }
        // Typing past a full field behaves like a normal maximum length.
        if activationText.count == 4, value.count == 5, value.hasPrefix(activationText),
           value.utf8.allSatisfy({ (65...90).contains($0) || (97...122).contains($0) }) { return }
        do { activationText = try PanelContract.subscriptionKeyInput(value); addition = .idle }
        catch { activationText = ""; addition = .failed(error.localizedDescription) }
    }
    func addSubscription() {
        guard !busy, addition != .added else { return }
        do {
            let key = try PanelContract.subscriptionKey(activationText)
            let trust = try activationTrust ?? PanelContract.bundled()
            activate(PanelActivation(code: key, trust: trust), name: UIDevice.current.name, reportingAddition: true)
        } catch { addition = .failed(error.localizedDescription) }
    }
    func receive(_ url: URL) {
        guard !busy else { showingSubscription = true; return }
        do {
            let bundled = try activationTrust ?? PanelContract.bundled()
            let input = try PanelContract.activation(url.absoluteString, bootstrap: bundled)
            guard bundled.sameSource(input.trust) else { throw PanelFailure("Use the 4-letter key supplied with your subscription.") }
            activationText = try PanelContract.subscriptionKey(input.code); addition = .idle
        } catch { activationText = ""; addition = .failed("Use the 4-letter key supplied with your subscription.") }
        showingSubscription = true
    }
    func isTrusted(_ trust: PanelTrust) -> Bool {
        ((try? (activationTrust ?? PanelContract.bundled()).sameSource(trust)) ?? false) || subscriptions.contains { $0.trust.sameSource(trust) }
    }
    func activate(_ input: PanelActivation, name: String, trustConfirmed: Bool = false, reportingAddition: Bool = false) {
        if reportingAddition && busy { return }
        guard trustConfirmed || isTrusted(input.trust) else {
            error = "Confirm this service's address and signing key before activating."; showingSubscription = true; return
        }
        let submittedText = activationText
        let key = "activate:" + input.trust.sourceID + ":" + PanelAssignedProfile.hashForOperation(input.code)
        if reportingAddition { addition = .adding; error = nil }
        enqueue(key, reportingAddition: reportingAddition) { [self] in
            try await client.activate(input, name: name, baseline: store.panelBaseline, manualIDs: store.manualProfileIDs)
            if activationText == submittedText { activationText = "" }
        }
    }
    func recoverSubscriptionCodes() {
        for sub in subscriptions where sub.subscriptionCode == nil && !sub.needsActivation {
            enqueue("code:" + sub.id, appliesSettings: false) { [self] in
                try await client.recoverSubscriptionCode(sub)
            }
        }
    }
    func refresh(_ sub: PanelSubscription) {
        guard !sub.needsActivation else { error = "Add this subscription again using its key."; return }
        enqueue("sync:" + sub.id) { [self] in
            try await client.sync(sub, baseline: store.panelBaseline, manualIDs: store.manualProfileIDs)
        }
    }
    func refreshAll() {
        guard !subscriptions.isEmpty else { showingSubscription = true; return }
        for sub in subscriptions { refresh(sub) }
    }
    func cancel() { for task in tasks.values { task.cancel() }; current?.cancel() }
    func remove(_ sub: PanelSubscription) {
        // Deletion is not a network operation. Its tombstone rejects any response
        // already in flight, including an activation with the same old request.
        do { try store.panelVault.transaction { $0.remove(sub.id) }; try store.reloadPanelProjection(); reload(); applyChanges() }
        catch { self.error = error.localizedDescription }
    }
    private func enqueue(_ key: String, reportingAddition: Bool = false, appliesSettings: Bool = true, operation: @escaping @MainActor () async throws -> Void) {
        guard tasks[key] == nil else { return }
        let previous = tail
        let task = Task { @MainActor [self] in
            await previous?.value
            defer {
                tasks.removeValue(forKey: key); pendingCount = tasks.count
                progress = ""; current = nil
                if reportingAddition && addition == .adding { addition = .idle }
            }
            guard !Task.isCancelled else { return }
            current = tasks[key]
            error = nil
            progress = PanelTransferRoute.direct.message
            let activity = PanelBackgroundActivity { [weak self] in self?.current?.cancel() }
            defer { activity.finish() }
            do {
                let lease = try store.panelVault.requestLease()
                // Hold the cross-process lease until native cleanup completes.
                defer { withExtendedLifetime(lease) {} }
                try Task.checkCancellation()
                try await operation()
                if appliesSettings { try store.reloadPanelProjection() }
                reload()
                if appliesSettings { applyChanges() }
                if reportingAddition { addition = .added }
            } catch is CancellationError { progress = "Cancelled. Saved settings were retained." }
            catch {
                if reportingAddition { addition = .failed(Self.additionError(error)) }
                else { self.error = error.localizedDescription }
                showingSubscription = true; reload()
            }
        }
        tasks[key] = task; pendingCount = tasks.count; tail = task
    }
    private static func additionError(_ error: Error) -> String {
        if let http = error as? PanelHTTPFailure {
            if http.code == "invalid_activation" { return "This key is invalid or expired. Check it and try again." }
            if http.code == "device_limit" { return "Device limit reached. Contact your subscription provider." }
            if http.code == "access_disabled" || http.code == "device_revoked" { return "This subscription is unavailable. Contact your provider." }
            if http.status == 429 { return "Too many attempts. Try again later." }
            if http.code == "provisioning_pending" { return "Your subscription is being prepared. Try again shortly." }
        }
        return "Could not add the subscription. Check your connection and try again."
    }
    func connectionAppliedSettings() { if vpn?.isConnected == true { reconnectRecommended = false } }
    func reconnectToApplySettings() {
        guard let runtime, let vpn, let id = runtime.activeProfileId,
              let profile = store.availableConfigurations.first(where: { $0.id == id }) else { return }
        Task { @MainActor in
            do {
                try PanelAccess.require(profile.profile.panelAccess, vault: store.panelVault)
                try await vpn.disconnectForImport()
                try runtime.prepare(profile)
                await vpn.connect(using: runtime)
                connectionAppliedSettings()
            } catch { self.error = error.localizedDescription; showingSubscription = true }
        }
    }
    private func applyChanges() {
        let oldSplit = runtime?.settings.splitTunneling, oldDNS = runtime?.settings.remoteDNS, oldVPNDNS = runtime?.settings.vpnDNS
        runtime?.applyPanelDNS(store.applicationDNSServers)
        runtime?.applySplitTunneling(store.splitTunneling)
        runtime?.applyAutomation(autoCaptcha: store.autoCaptcha, autoRecovery: store.autoRecovery, turnCheckInterval: store.turnCheckInterval)
        guard let runtime, let vpn else { return }
        if vpn.tunnelIsActive, oldSplit != runtime.settings.splitTunneling || oldDNS != runtime.settings.remoteDNS || oldVPNDNS != runtime.settings.vpnDNS {
            reconnectRecommended = true
        }
        Task { await vpn.applyAutomationSettings(using: runtime) }
        guard vpn.tunnelIsActive, let active = runtime.activeProfile, active.panelAccess != nil else { return }
        let replacement = store.configurations.first { $0.id == active.id }
        guard let replacement, (try? PanelAccess.require(replacement.profile.panelAccess, vault: store.panelVault)) != nil else { vpn.disconnect(); reconnectRecommended = false; return }
        if replacement.profile.panelAccess?.generation != active.panelAccess?.generation || replacement.profile.panelAccess?.credentialDigest != active.panelAccess?.credentialDigest {
            Task { @MainActor in
                do {
                    try await vpn.disconnectForImport()
                    try runtime.prepare(replacement)
                    await vpn.connect(using: runtime)
                    connectionAppliedSettings()
                } catch { self.error = error.localizedDescription }
            }
        }
    }
}

private extension PanelAssignedProfile {
    static func hashForOperation(_ value: String) -> String {
        // Never keep activation codes in operation identifiers or logs.
        SHA256.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined()
    }
}

@MainActor private final class PanelBackgroundActivity {
    private var id = UIBackgroundTaskIdentifier.invalid
    init(expired: @escaping @MainActor () -> Void) {
        id = UIApplication.shared.beginBackgroundTask(withName: "TnDtun subscription") { [weak self] in
            expired(); self?.finish()
        }
    }
    func finish() { guard id != .invalid else { return }; let saved = id; id = .invalid; UIApplication.shared.endBackgroundTask(saved) }
}

#if DEBUG
extension PanelManager {
    /// Signed, isolated UI-test responses. Synthetic keys never reach a real service.
    static func forUITesting(store: SimpleStore) -> PanelManager {
        let exchange = SubscriptionUIExchange(scenario: ProcessInfo.processInfo.environment["TNDTUN_UI_SUBSCRIPTION"] ?? "invalid")
        return PanelManager(store: store, client: PanelClient(vault: store.panelVault, exchange: exchange, pause: { _ in }), activationTrust: SubscriptionUIExchange.trust)
    }
}

private actor SubscriptionUIExchange: PanelExchanging {
    // A test-only signing key, unrelated to the bundled production pin.
    private static let signing = try! Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 73, count: 32))
    static let trust = PanelTrust(api: "https://subscription.example.test/v1", keyID: "1111111111111111",
        publicKey: PanelContract.base64URL(signing.publicKey.rawRepresentation),
        dns: PanelDNS(domain: "dns.example.test", publicKey: String(repeating: "ab", count: 32), resolver: "1.1.1.1:53"))
    private let scenario: String
    private var revision = Int64(0)
    init(scenario: String) { self.scenario = scenario }

    func post(trust: PanelTrust, dns: PanelDNS, path: String, body: Data, token: String?, deadline: Date) async throws -> Data {
        try await Task.sleep(for: .milliseconds(scenario == "slow" ? 5000 : 1000))
        let request = try PanelJSON.parse(body, limit: 16384)
        if path == "activate" {
            let code = try request.field("code").text()
            if scenario == "invalid" || code != "QWRT" { throw PanelHTTPFailure(status: 400, code: "invalid_activation") }
        }
        let device = "12345678-1234-1234-1234-123456789012"
        revision += 1
        let payload: [String: Any] = [
            "format": "TnDtun-package", "schema_version": 1, "revision": revision,
            "nonce": try request.field("nonce").text(), "issued_at": ISO8601DateFormatter().string(from: Date()),
            "client_id": "22345678-1234-1234-1234-123456789012", "client_name": "Test subscription", "device_id": device,
            "status": "active", "expires_at": NSNull(), "sync_after_seconds": 10,
            "settings": try JSONSerialization.jsonObject(with: JSONEncoder().encode(PanelSettings(
                autoCaptcha: true, autoRecovery: true, turnCheckInterval: 30, dnsServers: ["1.1.1.1:53"],
                dnsTunnel: Self.trust.dns, splitTunneling: SplitTunnelSettings()))),
            "profiles": [["id": "32345678-1234-1234-1234-123456789012", "mode": "turn", "generation": 1,
                "title": "Test connection", "location": "Test", "inbound_id": "test-inbound", "node_id": "test-node",
                "server": "203.0.113.8:56010", "callLink": "https://vk.ru/call/join/test",
                "vlessID": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "wrapKey": ""]]
        ]
        let bytes = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
        let envelope: [String: Any] = ["algorithm": "Ed25519", "key_id": trust.keyID,
            "payload": PanelContract.base64URL(bytes), "signature": PanelContract.base64URL(try Self.signing.signature(for: bytes))]
        if path == "sync" { return try JSONSerialization.data(withJSONObject: envelope) }
        return try JSONSerialization.data(withJSONObject: ["device_id": device, "token": "ui-test-only-token", "package": envelope])
    }
}
#endif
