import Foundation
import Network
import SystemDNS

public enum SystemDNSResolver {
    public struct NetworkSnapshot: Sendable {
        public let servers: [String]
        public let usesWiFi: Bool?
    }

    /// Read the physical network after the previous VPN has stopped. The bounded
    /// path lookup and resolver read run away from the UI thread.
    public static func networkSnapshot() async -> NetworkSnapshot {
        await Task.detached(priority: .userInitiated) { readNetworkSnapshot() }.value
    }

    private static func readNetworkSnapshot() -> NetworkSnapshot {
        let monitor = NWPathMonitor()
        let ready = DispatchSemaphore(value: 0)
        monitor.pathUpdateHandler = { _ in ready.signal() }
        monitor.start(queue: DispatchQueue(label: "TnDtun.dns-network-snapshot"))
        defer { monitor.cancel() }
        let receivedPath = ready.wait(timeout: .now() + 2) == .success
        let usesWiFi = receivedPath ? monitor.currentPath.usesInterfaceType(.wifi) : nil
        return NetworkSnapshot(servers: servers(), usesWiFi: usesWiFi)
    }

    /// Call before starting a VPN so the results describe the physical network.
    public static func servers() -> [String] {
        var buffer = [CChar](repeating: 0, count: 4096)
        let count = buffer.withUnsafeMutableBufferPointer { simple_copy_system_dns($0.baseAddress, $0.count) }
        guard count > 0 else { return [] }
        let text = String(decoding: buffer.prefix(Int(count)).map { UInt8(bitPattern: $0) }, as: UTF8.self)
        return text.split(separator: "\n").map(String.init).reduce(into: []) { values, address in
            if !values.contains(address) { values.append(address) }
        }
    }
}
