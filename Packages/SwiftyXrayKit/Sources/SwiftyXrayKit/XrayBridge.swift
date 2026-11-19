//
// XrayBridge.swift
// SwiftyXrayKit
//
// Copyright © 2025 Dmitry Ulyanov
//
// Bridges NEPacketTunnelFlow ↔ XRay's built-in gVisor tun inbound.
// XRay is configured with a "tun" protocol inbound; its fd is a SOCK_STREAM
// socketpair. No hev or SOCKS5 layer needed.
//
// Data flow:
//   packetFlow.readPackets → [4-byte AF header][IP packet] → socketpair fd[1]
//       → fd[0] → XRay gVisor → outbound proxy → remote
//   remote → outbound proxy → XRay gVisor → fd[0]
//       → fd[1] recv → [4-byte AF header][IP packet] → packetFlow.writePackets

import Foundation
@preconcurrency import NetworkExtension
import Darwin

public enum XrayBridgeError: Error {
    case socketPairFailed
    case invalidConfig
}

public protocol XrayPacketFlow: AnyObject {
    func readPackets(completionHandler: @escaping @Sendable ([Data], [NSNumber]) -> Void)
    @discardableResult func writePackets(_ packets: [Data], withProtocols protocols: [NSNumber]) -> Bool
}

extension NEPacketTunnelFlow: XrayPacketFlow {}

public final class XrayBridge: @unchecked Sendable {

    private weak var packetFlow: (any XrayPacketFlow)?
    private var swiftFd: Int32 = -1
    private var xrayFd: Int32 = -1
    private var isRunning = false // accessed on packetQueue
    private let packetQueue = DispatchQueue(label: "com.kindlyvpn.packet-flow")
    private let readThreads = DispatchGroup()
    private var packetReadPending = false

    private let statsLock = NSLock()
    private var _bytesReceived: Int64 = 0  // device ← remote (read thread)
    private var _bytesSent: Int64 = 0      // device → remote (packet flow)

    private var forwardingActive = false // accessed under statsLock
    private var failure: String?
    private var packetExchange: PacketExchange?

    /// A failed system-packet channel is independent of a working local proxy.
    public var forwardingFailure: String? {
        statsLock.lock(); defer { statsLock.unlock() }
        return failure
    }

    #if DEBUG
    public func simulatePacketReaderFailure() {
        packetQueue.async {
            if self.swiftFd >= 0 { Darwin.shutdown(self.swiftFd, SHUT_RD) }
        }
    }
    #endif

    /// Sends a diagnostic IP packet through the same TUN socket as device
    /// traffic. Its matching response is consumed before delivery to iOS.
    public func exchangePacket(_ packet: Data, family: UInt32, timeout: TimeInterval,
                               matching: @escaping @Sendable (Data, UInt32) -> Bool) async -> Data? {
        let exchange = PacketExchange(matching: matching)
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                exchange.attach(continuation)
                packetQueue.async {
                    guard !exchange.isFinished else { return }
                    self.statsLock.lock()
                    let available = self.forwardingActive && self.failure == nil && self.packetExchange == nil && !exchange.isFinished
                    if available { self.packetExchange = exchange }
                    self.statsLock.unlock()
                    guard available, self.isRunning, self.swiftFd >= 0 else {
                        self.finishExchange(exchange, response: nil); return
                    }
                    if !PacketStreamIO.writePacket(fd: self.swiftFd, packet: packet, family: family) {
                        self.recordFailure("System packet write failed (errno \(errno)).")
                        self.finishExchange(exchange, response: nil); return
                    }
                    self.packetQueue.asyncAfter(deadline: .now() + timeout) {
                        self.finishExchange(exchange, response: nil)
                    }
                }
            }
        } onCancel: { self.finishExchange(exchange, response: nil) }
    }

    private func finishExchange(_ exchange: PacketExchange, response: Data?) {
        statsLock.lock()
        if packetExchange === exchange { packetExchange = nil }
        statsLock.unlock()
        exchange.finish(response)
    }

    private func recordFailure(_ detail: String) {
        statsLock.lock()
        if forwardingActive && failure == nil { failure = detail }
        let exchange = packetExchange; packetExchange = nil
        statsLock.unlock()
        exchange?.finish(nil)
    }

    private func activateForwarding() {
        statsLock.lock(); forwardingActive = true; failure = nil; statsLock.unlock()
    }

    public init(packetFlow: any XrayPacketFlow) {
        self.packetFlow = packetFlow
    }

    deinit {
        if xrayFd >= 0 { Darwin.close(xrayFd) }
        if swiftFd >= 0 { Darwin.close(swiftFd) }
    }

    /// Starts XRay, building the config from `config` JSON.
    ///
    /// The kit injects the TUN inbound and optional sniffing, then calls
    /// `configTransform` (if provided) so you can mutate any part of the
    /// dictionary before it is written to `finalConfigPath` and run.
    ///
    /// - Parameters:
    ///   - config: Intermediate Xray JSON (outbounds, routing, etc. — no inbound needed).
    ///   - dataDir: Directory containing geo data files.
    ///   - finalConfigPath: Where the final JSON is written before running.
    ///   - sniffing: Optional sniffing injected into the TUN inbound.
    ///   - preset: Tuning preset to apply before run. Defaults to `.default`.
    ///   - configTransform: Optional closure receiving the kit-built config dictionary.
    ///                      Return a modified copy to customise anything before writing.
    ///   - traceHandle: Optional log sink for Xray lifecycle messages.
    public func start(
        config: XrayIntermediateConfig,
        dataDir: URL,
        finalConfigPath: URL,
        sniffing: SniffingConfiguration? = nil,
        preset: XrayTuningPreset = .default,
        configTransform: (([String: Any]) -> [String: Any])? = nil,
        traceHandle: ((String) -> Void)? = nil
    ) throws {
        let json: String
        switch config {
        case .json(let s): json = s
        case .url(let link): json = try SwiftyXray.xrayShareLinkToJson(url: link)
        }
        try openSocketPairAndApplyPreset(preset)
        var dict = try buildConfigDict(json: json, sniffing: sniffing)
        if let transform = configTransform { dict = transform(dict) }
        try writeAndRun(dict: dict, dataDir: dataDir, finalConfigPath: finalConfigPath, traceHandle: traceHandle)
    }

    /// Starts XRay with a fully pre-built config file — no patching applied.
    ///
    /// Use this when you want complete control over the Xray JSON.
    /// The kit only creates the socketpair and passes the fd to Xray before running.
    ///
    /// - Parameters:
    ///   - rawConfigPath: Path to your pre-built Xray config JSON.
    ///   - dataDir: Directory containing geo data files.
    ///   - preset: Tuning preset to apply before run. Defaults to `.default`.
    ///   - traceHandle: Optional log sink for Xray lifecycle messages.
    public func startWithRawConfig(
        rawConfigPath: URL,
        dataDir: URL,
        preset: XrayTuningPreset = .default,
        traceHandle: ((String) -> Void)? = nil
    ) throws {
        try openSocketPairAndApplyPreset(preset)
        try SwiftyXray.run(dataDir: dataDir.path, configPath: rawConfigPath.path, traceHandle: traceHandle)
        activateForwarding()
        launchReadThread(fd: swiftFd)
        packetQueue.sync {
            isRunning = true
            readFromPacketFlow()
        }
    }

    /// Returns the config dictionary that `start(config:…)` would produce,
    /// without writing or running anything. Use to inspect or test the output.
    public func buildConfig(
        config: XrayIntermediateConfig,
        sniffing: SniffingConfiguration? = nil,
        configTransform: (([String: Any]) -> [String: Any])? = nil
    ) throws -> [String: Any] {
        let json: String
        switch config {
        case .json(let s): json = s
        case .url(let link): json = try SwiftyXray.xrayShareLinkToJson(url: link)
        }
        var dict = try buildConfigDict(json: json, sniffing: sniffing)
        if let transform = configTransform { dict = transform(dict) }
        return dict
    }

    /// Stops XRay and closes the socketpair.
    public func stop() {
        // Wake blocked recv/writev before waiting for either worker. Keep the single
        // packetFlow read callback across restarts so two engines never race to read it.
        statsLock.lock()
        forwardingActive = false; failure = nil
        let exchange = packetExchange; packetExchange = nil
        statsLock.unlock()
        exchange?.finish(nil)
        let x = xrayFd, socket = swiftFd
        if socket >= 0 { Darwin.shutdown(socket, SHUT_RDWR) }
        packetQueue.sync {
            isRunning = false
            xrayFd = -1
            swiftFd = -1
        }
        readThreads.wait()
        try? SwiftyXray.stop()
        if x >= 0 { Darwin.close(x) }
        if socket >= 0 { Darwin.close(socket) }
    }

    /// Returns bytes transferred since last call and resets counters.
    public func getAndClearStats() -> BytesTransferred {
        statsLock.lock()
        let r = _bytesReceived
        let s = _bytesSent
        _bytesReceived = 0
        _bytesSent = 0
        statsLock.unlock()
        return BytesTransferred(received: max(0, r), sent: max(0, s))
    }

    // MARK: - Helpers

    private func openSocketPairAndApplyPreset(_ preset: XrayTuningPreset) throws {
        var fds: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0 else {
            throw XrayBridgeError.socketPairFailed
        }
        var noSigPipe: Int32 = 1
        setsockopt(fds[1], SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))
        packetQueue.sync {
            xrayFd = fds[0]
            swiftFd = fds[1]
        }
        SwiftyXray.setTunFd(xrayFd)
        preset.apply()
    }

    private func buildConfigDict(json: String, sniffing: SniffingConfiguration?) throws -> [String: Any] {
        guard let data = json.data(using: .utf8),
              var config = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw XrayBridgeError.invalidConfig
        }
        var inbound: [String: Any] = [
            "protocol": "tun",
            "settings": ["name": "utun9", "MTU": 1360],
            "tag": "in_proxy"
        ]
        if let sniffing {
            inbound["sniffing"] = [
                "destOverride": sniffing.destOverride,
                "enabled": sniffing.enabled,
                "routeOnly": sniffing.routeOnly,
                "metadataOnly": sniffing.metadataOnly,
                "domainsExcluded": sniffing.domainsExcluded
            ]
        }
        let additional = (config["inbounds"] as? [[String: Any]] ?? []).filter { $0["protocol"] as? String != "tun" }
        config["inbounds"] = [inbound] + additional
        return config
    }

    private func writeAndRun(
        dict: [String: Any],
        dataDir: URL,
        finalConfigPath: URL,
        traceHandle: ((String) -> Void)?
    ) throws {
        let data = try JSONSerialization.data(withJSONObject: dict, options: .prettyPrinted)
        let json = String(decoding: data, as: UTF8.self)
        traceHandle?("###XrayBridge final config: \(json)")
        try json.write(to: finalConfigPath, atomically: true, encoding: .utf8)
        try SwiftyXray.run(dataDir: dataDir.path, configPath: finalConfigPath.path, traceHandle: traceHandle)
        activateForwarding()
        launchReadThread(fd: swiftFd)
        packetQueue.sync {
            isRunning = true
            readFromPacketFlow()
        }
    }

    // MARK: - Threads

    // Reads packets from XRay (via fd[1]) and forwards them to the packet flow.
    // SOCK_STREAM format: [4-byte big-endian AF][raw IP packet], back-to-back in the stream.
    // Parses IP header length to find each packet boundary.
    // Exits when recv returns 0 or an error (fd closed by stop()).
    private func launchReadThread(fd: Int32) {
        guard let flow = packetFlow else { return }
        let group = readThreads
        group.enter()
        Thread.detachNewThread { [weak self] in
            defer { group.leave() }
            // The IPv6 payload limit excludes its 40-byte header.
            let capacity = 65535 + 40
            let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: capacity)
            defer { buffer.deallocate() }
            var keepRunning = true
            while keepRunning {
                autoreleasepool {
                    guard PacketStreamIO.readExactly(fd: fd, buffer: buffer, count: 4) else {
                        self?.recordFailure("System packet reader stopped (errno \(errno)).")
                        keepRunning = false; return
                    }
                    let family = buffer.withMemoryRebound(to: UInt32.self, capacity: 1) { UInt32(bigEndian: $0.pointee) }
                    guard family == UInt32(AF_INET) || family == UInt32(AF_INET6) else {
                        self?.recordFailure("Invalid system packet family: \(family).")
                        keepRunning = false; return
                    }
                    let header = family == UInt32(AF_INET) ? 20 : 40
                    guard PacketStreamIO.readExactly(fd: fd, buffer: buffer, count: header) else {
                        self?.recordFailure("Incomplete system IP header.")
                        keepRunning = false; return
                    }
                    let length: Int
                    if family == UInt32(AF_INET) {
                        length = Int(buffer[2]) << 8 | Int(buffer[3])
                        let ihl = Int(buffer[0] & 0x0f) * 4
                        guard buffer[0] >> 4 == 4, ihl >= 20, length >= ihl else {
                            self?.recordFailure("Invalid system IPv4 packet.")
                            keepRunning = false; return
                        }
                    } else {
                        length = header + (Int(buffer[4]) << 8 | Int(buffer[5]))
                        guard buffer[0] >> 4 == 6 else {
                            self?.recordFailure("Invalid system IPv6 packet.")
                            keepRunning = false; return
                        }
                    }
                    guard length <= capacity,
                          PacketStreamIO.readExactly(fd: fd, buffer: buffer + header, count: length - header) else {
                        self?.recordFailure("Incomplete system IP packet.")
                        keepRunning = false; return
                    }
                    let packet = Data(bytes: buffer, count: length)
                    if let self {
                        self.statsLock.lock()
                        let exchange = self.packetExchange
                        self.statsLock.unlock()
                        if let exchange, exchange.matching(packet, family) {
                            self.finishExchange(exchange, response: packet); return
                        }
                    }
                    guard flow.writePackets([packet], withProtocols: [NSNumber(value: family)]) else {
                        self?.recordFailure("iOS rejected a forwarded system packet.")
                        keepRunning = false; return
                    }
                    if let self {
                        self.statsLock.lock(); self._bytesReceived += Int64(packet.count); self.statsLock.unlock()
                    }
                }
            }
        }
    }

    // Reads packets from the system via packetFlow and forwards them to XRay (fd[1]).
    // Format written to fd: [4-byte big-endian AF][raw IP packet] as a single write.
    private func readFromPacketFlow() {
        guard isRunning, !packetReadPending, let packetFlow else { return }
        packetReadPending = true
        packetFlow.readPackets { [weak self] packets, protocols in
            self?.packetQueue.async { [weak self] in
                guard let self else { return }
                self.packetReadPending = false
                guard self.isRunning, self.swiftFd >= 0 else { return }
                let fd = self.swiftFd
                for (packet, proto) in zip(packets, protocols) {
                    guard PacketStreamIO.writePacket(fd: fd, packet: packet, family: proto.uint32Value) else {
                        self.recordFailure("System packet write failed (errno \(errno)).")
                        self.isRunning = false
                        return
                    }
                    self.statsLock.lock(); self._bytesSent += Int64(packet.count); self.statsLock.unlock()
                }
                self.readFromPacketFlow()
            }
        }
    }
}

/// A stream socket can return a short transfer or EINTR at any byte boundary.
/// Dropping a suffix corrupts every later AF/IP frame and leaves local proxy
/// health checks working while all system traffic is dead.
enum PacketStreamIO {
    static func readExactly(fd: Int32, buffer: UnsafeMutablePointer<UInt8>, count: Int,
                            receive: (Int32, UnsafeMutableRawPointer, Int) -> Int = { Darwin.recv($0, $1, $2, 0) }) -> Bool {
        var offset = 0
        while offset < count {
            let received = receive(fd, buffer + offset, count - offset)
            if received < 0 && errno == EINTR { continue }
            guard received > 0, received <= count - offset else { return false }
            offset += received
        }
        return true
    }

    static func writePacket(fd: Int32, packet: Data, family: UInt32,
                            send: (Int32, UnsafePointer<iovec>, Int32) -> Int = { Darwin.writev($0, $1, $2) }) -> Bool {
        var header = family.bigEndian
        return withUnsafeBytes(of: &header) { af in
            packet.withUnsafeBytes { bytes in
                guard let afBase = af.baseAddress, let packetBase = bytes.baseAddress else { return false }
                var vectors = [iovec(iov_base: UnsafeMutableRawPointer(mutating: afBase), iov_len: af.count),
                               iovec(iov_base: UnsafeMutableRawPointer(mutating: packetBase), iov_len: bytes.count)]
                var index = 0
                while index < vectors.count {
                    let written = vectors.withUnsafeBufferPointer { send(fd, $0.baseAddress! + index, Int32(vectors.count - index)) }
                    if written < 0 && errno == EINTR { continue }
                    guard written > 0 else { return false }
                    var remaining = written
                    while index < vectors.count && remaining >= vectors[index].iov_len {
                        remaining -= vectors[index].iov_len; index += 1
                    }
                    if index < vectors.count && remaining > 0 {
                        vectors[index].iov_base = vectors[index].iov_base!.advanced(by: remaining)
                        vectors[index].iov_len -= remaining
                    }
                }
                return true
            }
        }
    }
}

private final class PacketExchange: @unchecked Sendable {
    let matching: @Sendable (Data, UInt32) -> Bool
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data?, Never>?
    private var finished = false

    init(matching: @escaping @Sendable (Data, UInt32) -> Bool) { self.matching = matching }
    var isFinished: Bool { lock.lock(); defer { lock.unlock() }; return finished }
    func attach(_ value: CheckedContinuation<Data?, Never>) {
        lock.lock()
        if finished { lock.unlock(); value.resume(returning: nil) }
        else { continuation = value; lock.unlock() }
    }
    func finish(_ response: Data?) {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        finished = true
        let reply = continuation; continuation = nil
        lock.unlock()
        reply?.resume(returning: response)
    }
}
