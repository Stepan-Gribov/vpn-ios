import Foundation
import SwiftyXrayKit

@MainActor enum NativeTURNBridge {
    private static var transportPreference = TURNTransportPreference()

    static var isPlainVK: Bool {
        guard !usingDNS, !usingRecovery, !RecoveryTransportStore.enabled,
              let data = AppGroup.defaults.data(forKey: AppGroup.turnSettingsKey),
              let settings = try? JSONDecoder().decode(TURNSettings.self, from: data) else { return false }
        return settings.provider == .vk
    }

    static func resetTransportPreference() { transportPreference.reset() }

    static var supportsConnectionResume: Bool {
        isPlainVK && KindlyTurnRuntime.supportsConnectionResume
    }

    @discardableResult static func refreshResumableNetwork() -> Bool {
        supportsConnectionResume && KindlyTurnRuntime.refreshNetwork()
    }

    static func recordTransportFailure(previouslyConnected: Bool, networkSwitch: Bool) {
        guard isPlainVK else { return }
        transportPreference.failed(transport: status()?.transport, previouslyConnected: previouslyConnected, networkSwitch: networkSwitch)
    }
    private(set) static var usingDNS = false
    private(set) static var usingRecovery = false
    private static var usingTelemost = false
    private(set) static var currentDNSResolver: String?

    static func startIfNeeded(isTURN: Bool, isDNS: Bool = false, isManagedDNS: Bool = false, usingWiFi: Bool = false, builtInInterface: String? = nil) throws {
        usingDNS = isTURN && isDNS
        usingRecovery = isTURN && (isDNS || RecoveryTransportStore.enabled)
        guard isTURN else { return }
        if isManagedDNS {
            usingRecovery = false
            let settings = try ManagedDNSStore.load().validated()
            let data = try settings.runtimePayload(usingWiFi: usingWiFi, builtInInterface: builtInInterface)
            let result = KindlyTurnRuntime.start(configurationJSON: String(decoding: data, as: UTF8.self))
            guard result == 0 else { throw BridgeError.startFailed(Int(result)) }
            currentDNSResolver = settings.effectiveResolver(usingWiFi: usingWiFi)
            RuntimeLog.write("DNS transport preferred resolver: \(currentDNSResolver ?? "") · \(usingWiFi ? "Wi-Fi" : "mobile/other")")
            return
        }
        if usingRecovery {
            let data = try usingDNS ? RecoveryTransportStore.loadDNS() : RecoveryTransportStore.load()
            try startRecovery(data, port: usingDNS ? DNSConnection.port : 9000,
                              startAfter: usingDNS ? RecoveryTransportStore.dnsStartAfter : RecoveryTransportStore.startAfter)
            return
        }
        guard let data = AppGroup.defaults.data(forKey: AppGroup.turnSettingsKey),
              let settings = try? JSONDecoder().decode(TURNSettings.self, from: data) else {
            throw BridgeError.settingsMissing
        }
        var payload: [String: Any] = [
            "provider": settings.provider.rawValue,
            "peer_addr": settings.peer,
            "session_count": settings.sessionCount,
            "use_udp": settings.provider != .vk || !transportPreference.prefersTCP,
            "listen": "127.0.0.1:9000",
            "wrap_key": AppGroup.defaults.string(forKey: "simple.turn.wrapKey") ?? "",
            "auto_captcha": false,
        ]
        switch settings.provider {
        case .vk:
            guard let link = TURNSettings.normalizeVKCallLink(settings.vkCallLink) else { throw BridgeError.settingsMissing }
            payload["vk_link"] = link
        case .max:
            guard let token = TurnSecretStore.loadMAXToken(), !settings.maxPeerId.isEmpty else { throw BridgeError.settingsMissing }
            payload["max_token"] = token
            payload["max_peer_id"] = settings.maxPeerId
        }
        let json = try JSONSerialization.data(withJSONObject: payload)
        let value = String(data: json, encoding: .utf8) ?? "{}"
        let result = KindlyTurnRuntime.start(configurationJSON: value)
        guard result == 0 else { throw BridgeError.startFailed(Int(result)) }
        RuntimeLog.write("Native TURN helper started for \(settings.provider.title)")
    }

    static func startTelemost(_ data: Data) throws {
        usingDNS = false
        usingRecovery = true
        usingTelemost = true
        try startRecovery(data, port: 9000, startAfter: "")
    }

    private static func startRecovery(_ data: Data, port: Int, startAfter: String) throws {
        guard var config = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw BridgeError.settingsMissing }
        config["listen"] = "127.0.0.1:\(port)"
        config["start_after"] = startAfter
        let payload: [String: Any] = ["provider": "recovery", "recovery": config]
        let json = try JSONSerialization.data(withJSONObject: payload)
        let result = KindlyTurnRuntime.start(configurationJSON: String(decoding: json, as: UTF8.self))
        guard result == 0 else { throw BridgeError.startFailed(Int(result)) }
        RuntimeLog.write("Recovery transport supervisor started")
    }

    static func stop() {
        if isPlainVK { transportPreference.observe(transport: status()?.transport) }
        KindlyTurnRuntime.stop()
        usingDNS = false
        usingRecovery = false
        usingTelemost = false
        currentDNSResolver = nil
    }

    static func statusData() -> Data? {
        KindlyTurnRuntime.statusData()
    }

    static func status() -> RuntimeStatus? {
        guard let data = statusData() else { return nil }
        return try? JSONDecoder().decode(RuntimeStatus.self, from: data)
    }

    @discardableResult static func recordRouteFailure() -> Bool {
        guard !usingTelemost else { return false }
        guard usingRecovery, let status = status(), status.ready, let profile = status.profile else { return false }
        RecoveryTransportStore.recordFailure(profile: profile, dns: usingDNS)
        return true
    }

    struct RuntimeStatus: Decodable {
        let running: Bool
        let ready: Bool
        let transport: String
        let profile: String?
        let connectedStreams: Int
        let captchaRequired: Bool
        let captchaID: UInt64?
        let captchaAgeMilliseconds: Int64?
        let captchaURL: String?
        let detail: String?
        let lastError: String?

        enum CodingKeys: String, CodingKey {
            case running, ready, transport, profile
            case connectedStreams = "connected_streams"
            case captchaRequired = "captcha_required"
            case captchaID = "captcha_id"
            case captchaAgeMilliseconds = "captcha_age_ms"
            case captchaURL = "captcha_url"
            case detail
            case lastError = "last_error"
        }
    }
}

enum BridgeError: LocalizedError {
    case settingsMissing
    case startFailed(Int)

    var errorDescription: String? {
        switch self {
        case .settingsMissing: return "TURN is not configured."
        case .startFailed(-5): return "The previous transport is still stopping. We will reconnect automatically."
        case .startFailed(let code): return "Could not start TURN helper (\(code))."
        }
    }
}
