import Foundation
import Network
import Darwin
import LibXray

/// Separate exports, with no interaction with the Xray/TURN singleton.
public enum PanelTransportRuntime {
    public static func request(_ json: String) -> String { LibXrayKindlyPanelRequest(json) }
    public static func cancel(_ identifier: String) { LibXrayKindlyPanelCancel(identifier) }
    public static var activeRequests: Int { Int(LibXrayKindlyPanelActiveRequests()) }
}

public enum PhysicalDNSRuntime {
    public static func start(interface: String, resolvers: [String]) -> Int {
        let data = (try? JSONSerialization.data(withJSONObject: resolvers)) ?? Data("[]".utf8)
        return Int(LibXrayKindlyPhysicalDNSStart(interface, String(decoding: data, as: UTF8.self)))
    }
    public static func stop() { LibXrayKindlyPhysicalDNSStop() }
}

public struct PanelPhysicalNetwork: Sendable {
    public let interface: String
    public let wifi: Bool
    public let identity: String
    public let dnsServers: [String]

    /// Scoped monitors deliberately ignore a VPN's `other`/utun path. Resolver
    /// discovery is permitted only before a VPN starts; its DNS is never labelled
    /// carrier DNS. A VPN-active caller uses vetted built-in resolver candidates.
    public static func snapshot(readSystemDNS: Bool) async throws -> Self {
        try await Task.detached(priority: .userInitiated) { try readSnapshot(readSystemDNS: readSystemDNS) }.value
    }
    private static func readSnapshot(readSystemDNS: Bool) throws -> Self {
            let group = DispatchGroup()
            let queue = DispatchQueue(label: "TnDtun.panel.physical-path")
            let types: [NWInterface.InterfaceType] = [.wiredEthernet, .wifi, .cellular]
            let defaultMonitor = NWPathMonitor()
            let monitors = types.map { NWPathMonitor(requiredInterfaceType: $0) }
            for monitor in monitors + [defaultMonitor] {
                group.enter()
                let once = PanelPathOnce { group.leave() }
                monitor.pathUpdateHandler = { _ in once.finish() }
                monitor.start(queue: queue)
            }
            defer { (monitors + [defaultMonitor]).forEach { $0.cancel() } }
            _ = group.wait(timeout: .now() + 2)
            let defaultPath = defaultMonitor.currentPath
            let vpnPath = defaultPath.usesInterfaceType(.other)
            for (index, monitor) in monitors.enumerated() where monitor.currentPath.status == .satisfied {
                guard let interface = monitor.currentPath.availableInterfaces.first(where: {
                    $0.type == types[index] && !$0.name.hasPrefix("utun") && !$0.name.hasPrefix("lo")
                }) else { continue }
                let addresses = interfaceAddresses(interface.name)
                return Self(interface: interface.name, wifi: types[index] == .wifi,
                            identity: interface.name + ":" + addresses.joined(separator: ","),
                            dnsServers: readSystemDNS && !vpnPath ? SystemDNSResolver.servers() : [])
            }
            // Some simulator/Mac paths hide the physical interface behind the
            // active host VPN. Only enumerate real, up IP interfaces here; the
            // native socket is still strictly bound to that interface.
            for name in physicalInterfaceNames() {
                let addresses = interfaceAddresses(name)
                if !addresses.isEmpty {
                    return Self(interface: name, wifi: !name.hasPrefix("pdp_ip"),
                                identity: name + ":" + addresses.joined(separator: ","), dnsServers: [])
                }
            }
            throw NSError(domain: "TnDtun.Panel", code: 1, userInfo: [NSLocalizedDescriptionKey: "A physical Wi-Fi, Ethernet or mobile connection is required."])
    }
    private static func physicalInterfaceNames() -> [String] {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0 else { return [] }; defer { freeifaddrs(list) }
        var names = Set<String>(); var pointer = list
        while let item = pointer {
            defer { pointer = item.pointee.ifa_next }
            let name = String(cString: item.pointee.ifa_name)
            let flags = item.pointee.ifa_flags
            if (name.hasPrefix("en") || name.hasPrefix("pdp_ip")),
               flags & UInt32(IFF_UP | IFF_RUNNING) == UInt32(IFF_UP | IFF_RUNNING),
               item.pointee.ifa_addr?.pointee.sa_family == UInt8(AF_INET) || item.pointee.ifa_addr?.pointee.sa_family == UInt8(AF_INET6) {
                names.insert(name)
            }
        }
        return names.sorted()
    }
    /// Kernel addresses for interfaces selected by the existing path monitor.
    /// The virtual TUN and its installed routes never enter this identity.
    public static func addressIdentity(interfaces: [String]) -> String {
        interfaces.sorted().filter { !$0.hasPrefix("utun") && !$0.hasPrefix("lo") }
            .map { $0 + ":" + interfaceAddresses($0).joined(separator: ",") }.joined(separator: ";")
    }

    private static func interfaceAddresses(_ name: String) -> [String] {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0 else { return [] }
        defer { freeifaddrs(list) }
        var result: [String] = []; var pointer = list
        while let item = pointer {
            defer { pointer = item.pointee.ifa_next }
            guard String(cString: item.pointee.ifa_name) == name, let address = item.pointee.ifa_addr,
                  [AF_INET, AF_INET6].contains(Int32(address.pointee.sa_family)) else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(address, socklen_t(address.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 {
                result.append(String(decoding: host.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self))
            }
        }
        return result.sorted()
    }
}
private final class PanelPathOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var action: (() -> Void)?
    init(_ action: @escaping () -> Void) { self.action = action }
    func finish() { lock.lock(); let action = action; self.action = nil; lock.unlock(); action?() }
}
