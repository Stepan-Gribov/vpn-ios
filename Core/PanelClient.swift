import Foundation
import SwiftyXrayKit

struct PanelHTTPFailure: LocalizedError {
    var status: Int
    var code: String
    static func serviceCode(in body: Data) -> String {
        guard let error = try? PanelJSON.parse(body, limit: 16 * 1024),
              let code = try? error.field("code").text(64),
              code.range(of: "^[a-z_]{1,64}$", options: .regularExpression) != nil else { return "" }
        return code
    }
    var retryable: Bool { status == 429 || (status == 503 && code != "package_too_large") }
    var errorDescription: String? {
        if status == 401 { return "Reactivate this subscription. Your accepted profiles and settings were retained." }
        switch code {
        case "device_limit": return "The device limit has been reached. Contact your administrator."
        case "invalid_activation": return "The activation code is invalid or has expired."
        case "provisioning_pending": return "The server is preparing your connections. Please try again shortly."
        case "access_disabled", "device_revoked": return "The service refused this request. Previously accepted settings were retained."
        default: return status == 429 ? "Too many requests. Please try again later." : "The service is temporarily unavailable. Saved settings were retained."
        }
    }
}

struct PanelTransportFailure: LocalizedError {
    var errorDescription: String? { "The service could not be reached by HTTPS or the backup DNS channel. Your saved settings were retained." }
}

protocol PanelExchanging: Sendable {
    func post(trust: PanelTrust, dns: PanelDNS, path: String, body: Data, token: String?, deadline: Date) async throws -> Data
}

enum PanelTransferRoute: Equatable, Sendable {
    case direct, dns
    var message: String {
        self == .direct ? "Connecting to service…" : "Loading via DNS… This may take longer."
    }
}

enum PanelTransportSequence {
    /// Try the bundled HTTPS routes before spending the shared request budget
    /// on a single DNS tunnel to the primary. A service decision ends this search.
    static func run(apis: [String], forceDNS: Bool, progress: @Sendable (PanelTransferRoute) async -> Void,
                    request: (String, Bool) async throws -> PanelJSON) async throws -> (api: String, reply: PanelJSON) {
        try Task.checkCancellation()
        guard let primary = apis.first else { throw PanelFailure("Missing subscription service address.") }
        if !forceDNS {
            await progress(.direct)
            for api in apis {
                try Task.checkCancellation()
                let response = try await request(api, false)
                try Task.checkCancellation()
                let fields = try response.object
                if fields["error"] == .string("direct_unavailable") { continue }
                if fields["error"] == nil, apis.count > 1,
                   fields["status"] == .number("502") || fields["status"] == .number("504") {
                    let encoded = try fields["body"]?.text(24 * 1024) ?? ""
                    if let body = Data(base64Encoded: encoded), PanelHTTPFailure.serviceCode(in: body).isEmpty { continue }
                }
                return (api, response)
            }
        }
        try Task.checkCancellation()
        await progress(.dns)
        try Task.checkCancellation()
        let response = try await request(primary, true)
        try Task.checkCancellation()
        return (primary, response)
    }
}

enum PanelResolverCandidates {
    static func values(_ dns: PanelDNS, discovered: [String], wifi: Bool) -> [String] {
        let preferred = (dns.useWiFiResolver && wifi ? [dns.wifiResolver] : []) + (dns.autoDetectResolver ? discovered : [])
        let doh = ([dns.resolver] + dns.savedResolvers).compactMap { value -> String? in
            switch value {
            case "1.1.1.1:53", "1.0.0.1:53": return "https://cloudflare-dns.com/dns-query"
            case "8.8.8.8:53", "8.8.4.4:53": return "https://dns.google/dns-query"
            default: return nil
            }
        }
        let first = wifi && !dns.useWiFiResolver ? (dns.autoDetectResolver ? doh.sorted { ($0 == "https://dns.google/dns-query" ? 0 : 1) < ($1 == "https://dns.google/dns-query" ? 0 : 1) } : doh) : []
        return Array((first + Array(preferred.prefix(1)) + doh + [dns.resolver] + dns.savedResolvers + Array(preferred.dropFirst()))
            .reduce(into: [String]()) { if !$0.contains($1) { $0.append($1) } }.prefix(4))
    }
}

actor PanelNativeExchange: PanelExchanging {
    private let readSystemDNS: @Sendable () async -> Bool
    private let forceDNS: Bool
    private let progress: @Sendable (PanelTransferRoute) async -> Void
    private(set) var lastTransport = ""
    private(set) var lastAPI = ""
    private var lastNetwork = ""
    private var lastResolver: String?
    init(forceDNS: Bool = false, readSystemDNS: @escaping @Sendable () async -> Bool = { false },
         progress: @escaping @Sendable (PanelTransferRoute) async -> Void = { _ in }) {
        self.forceDNS = forceDNS; self.readSystemDNS = readSystemDNS; self.progress = progress
    }
    func post(trust: PanelTrust, dns: PanelDNS, path: String, body: Data, token: String?, deadline: Date) async throws -> Data {
        try Task.checkCancellation()
        let mayReadDNS = await readSystemDNS()
        let network = try await PanelPhysicalNetwork.snapshot(readSystemDNS: mayReadDNS)
        if lastNetwork != network.identity { lastNetwork = network.identity; lastResolver = nil }
        let service = try? PanelContract.bundledService()
        let endpoints = service?.endpoints(for: trust) ?? [trust]
        var transport = dns
        if transport.autoDetectResolver, let service, service.contains(trust) {
            transport.savedResolvers += trust.dns.savedResolvers + service.primary.dns.savedResolvers
        }
        var candidates = PanelResolverCandidates.values(transport, discovered: network.dnsServers, wifi: network.wifi)
        if let lastResolver, candidates.contains(lastResolver) { candidates.removeAll { $0 == lastResolver }; candidates.insert(lastResolver, at: 0) }
        let request: [String: Any] = ["key_id": trust.keyID, "public_key": trust.publicKey,
            "path": path, "body": String(decoding: body, as: UTF8.self), "token": token ?? "",
            "domain": transport.domain, "dns_key": transport.publicKey, "sessions": transport.sessionCount,
            "resolvers": candidates, "interface": network.interface, "physical_dns": network.dnsServers]
        let (responseAPI, result) = try await PanelTransportSequence.run(apis: endpoints.map(\.api), forceDNS: forceDNS, progress: progress) { api, viaDNS in
            var routed = request
            routed["api"] = api
            return try await self.perform(routed, viaDNS: viaDNS, deadline: deadline)
        }
        try Task.checkCancellation()
        if let error = try result.object["error"] {
            switch try error.text() {
            case "cancelled": throw CancellationError()
            case "untrusted_manifest": throw PanelFailure("The DNS route did not match the trusted service. No credentials were sent through it.")
            case "response_too_large": throw PanelFailure("The service response exceeds the supported size.")
            case "physical_network_unavailable": throw PanelFailure("The physical network is unavailable. Connect to Wi-Fi or mobile data and try again.")
            default: throw PanelTransportFailure()
            }
        }
        lastTransport = try result.field("transport").text(16)
        let status = Int(try result.field("status").integer)
        let encoded = try result.object["body"]?.text(18 * 1024 * 1024) ?? ""
        guard let bytes = Data(base64Encoded: encoded), bytes.count <= PanelContract.envelopeLimit else { throw PanelFailure("Invalid service response encoding.") }
        if let resolver = try result.object["resolver"], let value = try? resolver.text(2048), candidates.contains(value) { lastResolver = value }
        guard (200..<300).contains(status) else {
            throw PanelHTTPFailure(status: status, code: PanelHTTPFailure.serviceCode(in: bytes))
        }
        lastAPI = responseAPI
        return bytes
    }
    private func perform(_ base: [String: Any], viaDNS: Bool, deadline: Date) async throws -> PanelJSON {
        try Task.checkCancellation()
        guard deadline > Date() else { throw PanelTransportFailure() }
        let identifier = UUID().uuidString
        var request = base
        request["id"] = identifier
        request["force_dns"] = viaDNS
        request["direct_only"] = !viaDNS
        request["budget_seconds"] = max(1, min(192, Int(deadline.timeIntervalSinceNow)))
        let data = try JSONSerialization.data(withJSONObject: request)
        let worker = Task.detached(priority: .userInitiated) { PanelTransportRuntime.request(String(decoding: data, as: UTF8.self)) }
        let response = await withTaskCancellationHandler { await worker.value } onCancel: { PanelTransportRuntime.cancel(identifier) }
        try Task.checkCancellation()
        return try PanelJSON.parse(Data(response.utf8), limit: 20 * 1024 * 1024)
    }
}

struct PanelClient: Sendable {
    let vault: PanelVault
    let exchange: any PanelExchanging
    var pause: @Sendable (UInt64) async throws -> Void = { try await Task.sleep(nanoseconds: $0) }
    var now: @Sendable () -> Date = { Date() }
    var currentManualIDs: (@Sendable () throws -> Set<String>)?
    var serviceOverride: PanelServiceOrigins?

    func activate(_ input: PanelActivation, name: String, baseline: PanelSettings, manualIDs: Set<String>) async throws {
        guard (1...100).contains(name.utf16.count), !name.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else { throw PanelFailure("Enter a device name with 1–100 characters.") }
        let installation = try vault.installationID() // Committed before the first network call.
        let before = try vault.snapshot()
        let service = serviceOverride ?? (try? PanelContract.bundledService())
        let endpoints = service?.endpoints(for: input.trust) ?? [input.trust]
        let nonce = try PanelContract.nonce()
        #if targetEnvironment(macCatalyst)
        let platform = "macos"
        #else
        let platform = "ios"
        #endif
        let body = try JSONSerialization.data(withJSONObject: ["code": input.code, "installation_id": installation,
            "platform": platform, "name": name, "nonce": nonce])
        let raw = try await request(trust: input.trust, dns: input.trust.dns, path: "activate", body: body, token: nil)
        let response = try PanelJSON.parse(raw, limit: PanelContract.envelopeLimit)
        let device = try PanelContract.uuid(response.field("device_id"))
        let token = try response.field("token").text(4096)
        // A change of network address must not rename the vault record that the
        // packet tunnel, settings owner and existing profiles refer to.
        let previous = before.subscriptions.first { record in
            record.package.deviceID == device && endpoints.contains { $0.sameSource(record.trust) }
        }
        let storageTrust = previous?.trust ?? input.trust
        let id = storageTrust.api + "#" + device
        let packet = try PanelContract.verify(response.field("package").encoded(), trust: input.trust, nonce: nonce, deviceID: device, previous: previous)
        try Task.checkCancellation()
        try vault.transaction { state in
            let currentIDs = try currentManualIDs?() ?? manualIDs
            guard endpoints.allSatisfy({ state.sourceEpochs[$0.api, default: 0] == before.sourceEpochs[$0.api, default: 0] }) else {
                throw PanelFailure("This subscription was removed while the request was running.")
            }
            try state.accept(packet, trust: storageTrust, token: token, expectedEpoch: before.sourceEpochs[storageTrust.api, default: 0], activation: true,
                             manualIDs: currentIDs, baseline: baseline, now: Int64(now().timeIntervalSince1970))
            if let index = state.subscriptions.firstIndex(where: { $0.id == id }) {
                state.subscriptions[index].subscriptionCode = packet.subscriptionCode ?? input.code
            }
        }
    }
    /// Backfill legacy display metadata without replacing profiles, tokens,
    /// global settings, revision or the active VPN configuration.
    func recoverSubscriptionCode(_ subscription: PanelSubscription) async throws {
        let before = try vault.snapshot()
        guard let current = before.subscriptions.first(where: { $0.id == subscription.id }),
              current.subscriptionCode == nil, !current.needsActivation else { return }
        let nonce = try PanelContract.nonce()
        let body = try JSONSerialization.data(withJSONObject: ["nonce": nonce, "known_revision": current.package.revision])
        let raw = try await request(trust: current.trust, dns: current.package.settings?.dnsTunnel ?? current.trust.dns,
                                    path: "sync", body: body, token: current.token)
        let packet = try PanelContract.verify(raw, trust: current.trust, nonce: nonce,
                                             deviceID: current.package.deviceID, previous: current)
        guard let code = packet.subscriptionCode else { return }
        try Task.checkCancellation()
        try vault.transaction { state in
            guard state.sourceEpochs[current.trust.api, default: 0] == before.sourceEpochs[current.trust.api, default: 0],
                  let index = state.subscriptions.firstIndex(where: { $0.id == current.id && $0.token == current.token }) else { return }
            state.subscriptions[index].subscriptionCode = code
        }
    }

    func sync(_ subscription: PanelSubscription, baseline: PanelSettings, manualIDs: Set<String>) async throws {
        let before = try vault.snapshot()
        guard let current = before.subscriptions.first(where: { $0.id == subscription.id }) else { throw PanelFailure("This subscription was removed.") }
        let nonce = try PanelContract.nonce()
        let body = try JSONSerialization.data(withJSONObject: ["nonce": nonce, "known_revision": current.package.revision])
        let raw: Data
        do { raw = try await request(trust: current.trust, dns: current.package.settings?.dnsTunnel ?? current.trust.dns, path: "sync", body: body, token: current.token) }
        catch let error as PanelHTTPFailure {
            if error.status == 401 {
                try vault.transaction { state in
                    guard state.sourceEpochs[current.trust.api, default: 0] == before.sourceEpochs[current.trust.api, default: 0] else { return }
                    if let index = state.subscriptions.firstIndex(where: { $0.id == current.id && $0.token == current.token }) { state.subscriptions[index].needsActivation = true }
                }
            }
            throw error
        }
        let packet = try PanelContract.verify(raw, trust: current.trust, nonce: nonce, deviceID: current.package.deviceID, previous: current)
        try Task.checkCancellation()
        try vault.transaction { state in
            let currentIDs = try currentManualIDs?() ?? manualIDs
            try state.accept(packet, trust: current.trust, token: current.token, expectedEpoch: before.sourceEpochs[current.trust.api, default: 0],
                             activation: false, manualIDs: currentIDs, baseline: baseline, now: Int64(now().timeIntervalSince1970))
        }
    }
    private func request(trust: PanelTrust, dns: PanelDNS, path: String, body: Data, token: String?) async throws -> Data {
        let deadline = now().addingTimeInterval(192)
        for attempt in 0..<3 {
            do { return try await exchange.post(trust: trust, dns: dns, path: path, body: body, token: token, deadline: deadline) }
            catch {
                try Task.checkCancellation()
                let retry = (error as? PanelHTTPFailure)?.retryable ?? ((error is URLError) || (error is PanelTransportFailure))
                guard retry, attempt < 2, deadline.timeIntervalSince(now()) > 10 else { throw error }
                try await pause(UInt64((2_000 << attempt) + Int.random(in: 0..<1500)) * 1_000_000)
            }
        }
        throw PanelFailure("The service is unavailable.")
    }
}
