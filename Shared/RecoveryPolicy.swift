import Foundation
import Network
import Darwin

enum ConnectionDropPolicy {
    static let probeTimeout: TimeInterval = 15
    static let retryCooldown: TimeInterval = 30
    static let transportDropGrace: TimeInterval = 15

    static func isUnexpected(connectionWasActive: Bool, shutdownExpected: Bool) -> Bool {
        connectionWasActive && !shutdownExpected
    }

    static func shouldReconnect(autoReconnectEnabled: Bool, unexpected: Bool) -> Bool {
        autoReconnectEnabled && unexpected
    }

    static func turnReadyTimeout(captchaPending: Bool, autoCaptcha: Bool) -> TimeInterval {
        // Pending means the automatic solver has already handed off to the user.
        // Give that fallback the same five-minute window in either mode.
        captchaPending ? 300 : (autoCaptcha ? 180 : 90)
    }
}

/// The native challenge clock survives browser reloads, app suspension and
/// migration checks. The saved automation preference is never changed by handoff.
enum TURNCaptchaPolicy {
    static let automaticWindow: TimeInterval = 45
    static let lifetime: TimeInterval = 300

    static func needsUser(ageMilliseconds: Int64, automatic: Bool) -> Bool {
        !automatic || Double(ageMilliseconds) / 1_000 >= automaticWindow
    }

    static func expired(ageMilliseconds: Int64) -> Bool {
        Double(ageMilliseconds) / 1_000 >= lifetime
    }

    static func terminalFailure(_ error: String?) -> Bool {
        guard let error else { return false }
        return error.contains("FATAL_CAPTCHA") || error.contains("manual captcha timed out")
    }
}

enum TURNHealthCheckPolicy {
    static let defaultInterval = 30
    static let intervals = [15, 30, 60, 120, 300]

    static func interval(_ seconds: Int?) -> Int {
        min(300, max(15, seconds ?? defaultInterval))
    }

    static func label(_ seconds: Int) -> String {
        seconds % 60 == 0 ? "\(seconds / 60) min" : "\(seconds) sec"
    }
}

/// Uses the provider's monotonic clock, independent of the containing app.
/// Reading the interval at each tick applies saved changes without restarting
/// the tunnel. Slow probes start a fresh interval when they finish.
struct BackgroundProbeSchedule {
    private var lastCompletedAt: TimeInterval

    init(now: TimeInterval) { lastCompletedAt = now }

    func isDue(now: TimeInterval, interval: Int) -> Bool {
        now - lastCompletedAt >= Double(interval)
    }

    mutating func completed(at now: TimeInterval) { lastCompletedAt = now }
}

/// The saved automation switch belongs to TURN proxy, not to every transport
/// implemented by the native TURN bridge (which also hosts DNSTT).
struct TunnelAutomationPolicy {
    let isTURNProxy: Bool

    init(isTURN: Bool, isDNS: Bool = false, isManagedDNS: Bool = false, isAmnezia: Bool = false) {
        isTURNProxy = isTURN && !isDNS && !isManagedDNS && !isAmnezia
    }

    init(profile: VPNProfile) {
        self.init(isTURN: profile.isTURN, isDNS: profile.isDNS,
                  isManagedDNS: profile.isManagedDNS, isAmnezia: profile.isAmnezia)
    }

    func automaticRecoveryEnabled(_ settings: AppSettings) -> Bool {
        isTURNProxy && settings.isAutoReconnectOnDropEnabled
    }

    func onDemandEnabled(_ settings: AppSettings) -> Bool {
        automaticRecoveryEnabled(settings) && settings.connectOnDemand
    }

    func permitsRecovery(manual: Bool, settings: AppSettings) -> Bool {
        manual || automaticRecoveryEnabled(settings)
    }
}

/// Unlike a loopback proxy request, this traverses the AF/IP socket, the TUN
/// inbound and the system DNS routing rule, then waits for an IP reply.
struct TunnelDNSProbe: Sendable {
    let packet: Data
    private let transaction: UInt16
    private let sourcePort: UInt16
    private let server: Data
    private static let source = Data([198, 18, 0, 2])

    init?(server: String, domain: String = "www.gstatic.com") {
        guard let address = IPv4Address(server) else { return nil }
        self.server = address.rawValue
        transaction = UInt16.random(in: 1...UInt16.max)
        sourcePort = UInt16.random(in: 49152...65535)
        func word(_ value: UInt16) -> [UInt8] { [UInt8(value >> 8), UInt8(value & 0xff)] }
        var dns = word(transaction) + [1, 0, 0, 1, 0, 0, 0, 0, 0, 0]
        for label in domain.split(separator: ".") {
            let bytes = Array(label.utf8)
            guard !bytes.isEmpty, bytes.count <= 63 else { return nil }
            dns += [UInt8(bytes.count)] + bytes
        }
        dns += [0, 0, 1, 0, 1] // A, IN
        let udp = word(sourcePort) + word(53) + word(UInt16(8 + dns.count)) + [0, 0]
        var ip: [UInt8] = [0x45, 0] + word(UInt16(20 + udp.count + dns.count)) + [0, 0, 0, 0, 64, 17, 0, 0]
        ip += Self.source + self.server
        var checksum: UInt32 = 0
        for index in stride(from: 0, to: ip.count, by: 2) { checksum += UInt32(ip[index]) << 8 | UInt32(ip[index + 1]) }
        while checksum > 0xffff { checksum = (checksum & 0xffff) + (checksum >> 16) }
        let sum = ~UInt16(checksum)
        ip[10] = UInt8(sum >> 8); ip[11] = UInt8(sum & 0xff)
        packet = Data(ip + udp + dns)
    }

    func matches(_ packet: Data, family: UInt32) -> Bool {
        guard family == UInt32(AF_INET), packet.count >= 40, packet[0] >> 4 == 4, packet[9] == 17,
              Data(packet[12..<16]) == server, Data(packet[16..<20]) == Self.source else { return false }
        let header = Int(packet[0] & 0x0f) * 4
        guard header >= 20, packet.count >= header + 20 else { return false }
        func word(_ index: Int) -> UInt16 { UInt16(packet[index]) << 8 | UInt16(packet[index + 1]) }
        return word(header) == 53 && word(header + 2) == sourcePort && word(header + 8) == transaction
    }

    func succeeded(_ packet: Data) -> Bool {
        guard matches(packet, family: UInt32(AF_INET)) else { return false }
        let dns = Int(packet[0] & 0x0f) * 4 + 8
        return packet[dns + 2] & 0x80 != 0 && packet[dns + 3] & 0x0f == 0 &&
            (packet[dns + 6] != 0 || packet[dns + 7] != 0)
    }
}

enum RecoveryPhase: String, Codable {
    case disconnected, connected, waitingForNetwork, retryWait, stopping
    case startingTURN, startingCore, captcha, verifying, failed

    var isRecovering: Bool { self != .connected && self != .disconnected && self != .failed }
}

struct TunnelRecoverySnapshot: Codable, Equatable {
    var providerProcessID: Int?
    var providerRestartRequested: Bool?
    var phase: RecoveryPhase = .disconnected
    var profileID: String = ""
    var attempt = 0
    var maximumAttempts = 5
    var latencyMilliseconds: Int?
    var detail = ""
    var updatedAt = Date()
}

/// One bounded sequence. Waiting for connectivity never consumes a retry.
struct RecoveryBudget {
    enum Decision: Equatable { case waitForNetwork, attempt(Int), exhausted }
    private(set) var attempts = 0
    private(set) var consecutiveFailures = 0

    mutating func next(networkAvailable: Bool, maximum: Int) -> Decision {
        guard networkAvailable else { return .waitForNetwork }
        guard attempts < min(20, max(1, maximum)) else { return .exhausted }
        attempts += 1
        return .attempt(attempts)
    }

    mutating func recordProbe(succeeded: Bool, failureThreshold: Int = 2) -> Bool {
        consecutiveFailures = succeeded ? 0 : consecutiveFailures + 1
        return consecutiveFailures >= max(1, failureThreshold)
    }

    mutating func restored() { attempts = 0; consecutiveFailures = 0 }
    // A burst is bounded, but automatic recovery must stay alive while the app
    // is suspended. The provider waits before starting the next burst.
    mutating func resumeAfterCooldown() { attempts = 0 }
}

struct HTTPProbeRequest {
    // Manual RealDelay: one fresh HTTPS request, including DNS/TCP/TLS when needed.
    static let realDelayURL = "https://www.gstatic.com/generate_204"
    static let realDelayTimeout: TimeInterval = 10
    static let realDelay = HTTPProbeRequest(realDelayURL, expectedStatusCode: 204)!
    // Existing connectivity checks retain their own targets and fallback policy.
    static let turnURL = "https://1.1.1.1/cdn-cgi/trace"
    static let recoveryURL = "https://www.gstatic.com/generate_204"
    static let systemFallbackURL = "https://www.apple.com/library/test/success.html"
    let host: String
    let port: Int
    let tls: Bool
    let data: Data
    let expectedStatusCode: Int?

    init?(_ rawURL: String, expectedStatusCode: Int? = nil) {
        guard let url = URL(string: rawURL), let host = url.host,
              ["http", "https"].contains(url.scheme?.lowercased() ?? ""),
              url.user == nil, url.password == nil else { return nil }
        self.host = host.hasPrefix("[") && host.hasSuffix("]") ? String(host.dropFirst().dropLast()) : host
        self.expectedStatusCode = expectedStatusCode
        tls = url.scheme?.lowercased() == "https"
        port = url.port ?? (tls ? 443 : 80)
        guard (1...65535).contains(port) else { return nil }
        let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
        var path = components?.percentEncodedPath ?? "/"
        if path.isEmpty { path = "/" }
        if let query = components?.percentEncodedQuery { path += "?" + query }
        let hostHeader = host.contains(":") && !host.hasPrefix("[") ? "[\(host)]" : host
        let authority = hostHeader + (url.port == nil ? "" : ":\(port)")
        data = Data("GET \(path) HTTP/1.1\r\nHost: \(authority)\r\nConnection: close\r\nCache-Control: no-cache\r\n\r\n".utf8)
    }

    static func turnFallback(_ rawURL: String) -> HTTPProbeRequest? {
        if let request = HTTPProbeRequest(rawURL), request.tls { return request }
        return HTTPProbeRequest(systemFallbackURL, expectedStatusCode: 200)
    }

    static func successfulResponse(_ data: Data, expectedStatusCode: Int? = nil) -> Bool? {
        guard let end = data.range(of: Data("\r\n".utf8)) else {
            return data.count >= 4096 ? false : nil
        }
        let line = String(decoding: data[..<end.lowerBound], as: UTF8.self).split(separator: " ")
        guard line.count >= 2, ["HTTP/1.0", "HTTP/1.1"].contains(line[0]), let code = Int(line[1]) else { return false }
        if let expectedStatusCode { return code == expectedStatusCode }
        return (200..<300).contains(code)
    }
}

/// Loopback-only access to the chosen proxy, ahead of user bypass rules.
struct ProbeConfiguration {
    static func adding(to root: [String: Any], port: Int, request: HTTPProbeRequest, tag: String = "kindly-health") -> [String: Any] {
        var result = root
        var inbounds = result["inbounds"] as? [[String: Any]] ?? []
        inbounds.append([
            "tag": tag, "listen": "127.0.0.1", "port": port,
            "protocol": "dokodemo-door",
            "settings": ["address": request.host, "port": request.port, "network": "tcp"],
        ])
        result["inbounds"] = inbounds
        var routing = result["routing"] as? [String: Any] ?? [:]
        var rules = routing["rules"] as? [[String: Any]] ?? []
        rules.insert(["type": "field", "inboundTag": [tag], "outboundTag": "proxy"], at: 0)
        routing["rules"] = rules
        result["routing"] = routing
        return result
    }
}

/// Preference belongs to one explicit VPN connection, not one helper lifetime.
struct TURNTransportPreference {
    private(set) var prefersTCP = false

    mutating func observe(transport: String?) {
        if transport == "tcp" { prefersTCP = true }
    }
    mutating func failed(transport: String?, previouslyConnected: Bool, networkSwitch: Bool) {
        observe(transport: transport)
        if previouslyConnected && !networkSwitch && transport == "udp" { prefersTCP = true }
    }
    mutating func reset() { prefersTCP = false }
}

/// All synchronous helper mutations run on the same actor as Stop. An await
/// can invalidate the attempt, so check again immediately before each mutation
/// and before accepting verification. This driver also supports deterministic
/// cancellation/network-change fixtures without creating a system VPN.
@MainActor enum TURNRelayRepair {
    static func run(isCurrent: () -> Bool,
                    resume: (() async throws -> Int?)? = nil,
                    stop: () -> Void,
                    prepare: () async throws -> Void,
                    start: () throws -> Void,
                    waitForReady: () async throws -> Void,
                    verify: () async -> Int?) async throws -> Int {
        guard isCurrent(), !Task.isCancelled else { throw CancellationError() }
        if let resume {
            let latency = try await resume()
            guard isCurrent(), !Task.isCancelled else { throw CancellationError() }
            if let latency { return latency }
        }
        stop()
        try await prepare()
        guard isCurrent(), !Task.isCancelled else { throw CancellationError() }
        try start()
        try await waitForReady()
        guard isCurrent(), !Task.isCancelled else { throw CancellationError() }
        let latency = await verify()
        guard isCurrent(), !Task.isCancelled else { throw CancellationError() }
        guard let latency else { throw VerificationFailure() }
        return latency
    }
    struct VerificationFailure: LocalizedError {
        var errorDescription: String? { "TURN DNS or HTTPS verification failed." }
    }
}

/// Repair only a reported local packet-channel error, once. Wake, app
/// visibility and a failed remote ping must never enter this operation.
enum AmneziaPacketRepair {
    struct Unavailable: Error {}
    @MainActor static func run(isCurrent: () -> Bool,
                               packetChannelFailed: () -> Bool,
                               repair: () async throws -> Void,
                               verify: () async -> Int?) async throws -> Int? {
        guard isCurrent(), !Task.isCancelled else { throw CancellationError() }
        guard packetChannelFailed() else { return nil }
        try await repair()
        guard isCurrent(), !Task.isCancelled else { throw CancellationError() }
        let latency = await verify()
        guard isCurrent(), !Task.isCancelled else { throw CancellationError() }
        guard let latency else { throw Unavailable() }
        return latency
    }
}

/// Brief physical-network gaps are normal during Wi-Fi/cellular handoff.
/// Failures only accumulate on the same stable path.
struct AmneziaHealthPolicy {
    private var observedPath: UInt64?
    private var offlineSince: TimeInterval?
    private(set) var failures = 0

    mutating func observeNetwork(available: Bool, revision: UInt64, now: TimeInterval) -> Bool {
        if observedPath != revision { observedPath = revision; failures = 0 }
        if available { offlineSince = nil; return false }
        if offlineSince == nil { offlineSince = now }
        return now - (offlineSince ?? now) >= 3
    }

    mutating func recordProbe(succeeded: Bool, revision: UInt64) -> Bool {
        guard observedPath == revision else { failures = 0; return false }
        failures = succeeded ? 0 : failures + 1
        return failures >= 2
    }
}

/// Share a finite deadline across independent endpoints without letting a
/// timed-out primary starve the fallback or the final packet-path check.
@MainActor enum RouteProbeSequence {
    static func measure(deadline: TimeInterval?, reservedAfter: TimeInterval = 0,
                        now: () -> TimeInterval, isCurrent: () -> Bool,
                        primary: (TimeInterval) async -> Int?,
                        fallback: ((TimeInterval) async -> Int?)?) async -> Int? {
        func remaining() -> TimeInterval {
            guard let deadline else { return ConnectionDropPolicy.probeTimeout }
            return max(0, deadline - now() - reservedAfter)
        }
        guard isCurrent(), !Task.isCancelled else { return nil }
        let firstBudget = min(ConnectionDropPolicy.probeTimeout,
                              remaining() / (deadline != nil && fallback != nil ? 2 : 1))
        guard firstBudget > 0 else { return nil }
        let result = await primary(firstBudget)
        guard isCurrent(), !Task.isCancelled else { return nil }
        if let result { return result }
        guard let fallback else { return nil }
        let secondBudget = min(ConnectionDropPolicy.probeTimeout, remaining())
        guard secondBudget > 0 else { return nil }
        let second = await fallback(secondBudget)
        return isCurrent() && !Task.isCancelled ? second : nil
    }
}

/// Owns a live Amnezia provider's recovery; it never needs the containing app
/// or On Demand. Only verified transport is allowed to recapture system traffic.
@MainActor enum AmneziaRecoveryCoordinator {
    static let maximumCapturedRecovery: TimeInterval = 30
    static let attemptTimeout: TimeInterval = 15
    static let delays = [15, 30, 60, 120, 300]

    enum Stage: Equatable { case repairing, waitingForNetwork, standby(Int), restoring }
    struct Hooks {
        var isCurrent: () -> Bool
        var networkAvailable: () -> Bool
        var pathRevision: () -> UInt64
        var now: () -> TimeInterval
        var pause: (TimeInterval) async throws -> Void
        var softRepair: () -> Void
        var rebuild: () async throws -> Void
        var release: () async throws -> Void
        var restore: () async throws -> Void
        var verify: (_ deadline: TimeInterval, _ transportOnly: Bool) async -> Int?
        var update: (Stage, Int) -> Void
    }

    static func run(_ hooks: Hooks, packetChannelFailed: Bool) async throws -> Int {
        func check() throws {
            guard hooks.isCurrent(), !Task.isCancelled else { throw CancellationError() }
        }
        func samePath(_ revision: UInt64) -> Bool {
            hooks.networkAvailable() && hooks.pathRevision() == revision
        }
        // Only the bounded, non-destructive socket rebind keeps the old
        // routes. A packet failure or failed rebind releases them before any
        // potentially slow DNS preparation/native engine reconstruction.
        try check()
        if !packetChannelFailed, hooks.networkAvailable() {
            let revision = hooks.pathRevision()
            hooks.update(.repairing, 0)
            hooks.softRepair()
            let deadline = hooks.now() + min(maximumCapturedRecovery, attemptTimeout)
            let latency = await hooks.verify(deadline, false)
            try check()
            if samePath(revision), let latency { return latency }
        }
        try check()
        // A clear failure is terminal for the caller: never sleep with dead
        // routes installed. Successful clearing preserves the live provider.
        try await hooks.release()
        try check()
        var failures = 0
        var observedPath = hooks.pathRevision()
        var retryAt = hooks.now()
        while true {
            try check()
            if hooks.pathRevision() != observedPath {
                observedPath = hooks.pathRevision()
                retryAt = hooks.now()
                failures = 0
            }
            guard hooks.networkAvailable() else {
                hooks.update(.waitingForNetwork, failures)
                try await hooks.pause(1)
                continue
            }
            if hooks.now() < retryAt {
                hooks.update(.standby(Int(ceil(retryAt - hooks.now()))), failures)
                try await hooks.pause(min(1, retryAt - hooks.now()))
                continue
            }
            let revision = hooks.pathRevision()
            hooks.update(.repairing, failures)
            do {
                try await hooks.rebuild()
                try check()
                if samePath(revision) {
                    let preflight = await hooks.verify(hooks.now() + attemptTimeout, true)
                    try check()
                    if samePath(revision), preflight != nil {
                        hooks.update(.restoring, failures)
                        // Conservatively clear after any restore error: it may
                        // have applied settings before reporting an error.
                        try await hooks.restore()
                        try check()
                        if samePath(revision) {
                            let latency = await hooks.verify(hooks.now() + attemptTimeout, false)
                            try check()
                            if samePath(revision), let latency { return latency }
                        }
                    }
                }
            } catch {
                try check()
            }
            // Also stops the unsuccessful native engine. Every wait and every
            // subsequent preflight runs with ordinary system routes and DNS.
            try await hooks.release()
            try check()
            guard samePath(revision) else {
                // A vanished/changed physical network is not a server failure.
                // The new path must not inherit the old path's backoff.
                retryAt = hooks.now()
                failures = 0
                continue
            }
            failures += 1
            retryAt = hooks.now() + Double(delays[min(failures - 1, delays.count - 1)])
        }
    }
}

/// A user action wins even if the initial preferences load is still suspended.
struct AppLaunchIntent {
    private var consumed = false
    mutating func claim() -> Bool {
        guard !consumed else { return false }
        consumed = true
        return true
    }
    mutating func cancel() { consumed = true }
}
