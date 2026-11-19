import Foundation
import Network
import Security

final class ForwardedProbe: @unchecked Sendable {
    private let queue = DispatchQueue(label: "com.kindlyvpn.profile-probe")
    private var connection: NWConnection?
    private var continuation: CheckedContinuation<Int?, Never>?
    private var response = Data()
    private var finished = false
    private var timeout = ConnectionDropPolicy.probeTimeout
    private var started: TimeInterval = 0

    static func measure(port: Int, request: HTTPProbeRequest, timeout: TimeInterval = ConnectionDropPolicy.probeTimeout) async -> Int? {
        await measure(host: "127.0.0.1", port: port, interface: nil, request: request, timeout: timeout)
    }

    /// A required virtual interface makes the request cross macOS/iOS packetFlow.
    /// A working loopback proxy, or a direct physical route, cannot satisfy it.
    static func measureThroughInterface(_ interface: NWInterface, request: HTTPProbeRequest,
                                        timeout: TimeInterval = ConnectionDropPolicy.probeTimeout) async -> Int? {
        await measure(host: request.host, port: request.port, interface: interface, request: request, timeout: timeout)
    }

    private static func measure(host: String, port: Int, interface: NWInterface?, request: HTTPProbeRequest,
                                timeout: TimeInterval) async -> Int? {
        let probe = ForwardedProbe()
        probe.timeout = timeout
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                probe.queue.async { probe.start(host: host, port: port, interface: interface, request: request, continuation: continuation) }
            }
        } onCancel: { probe.queue.async { probe.finish(nil) } }
    }

    private func start(host: String, port: Int, interface: NWInterface?, request: HTTPProbeRequest, continuation: CheckedContinuation<Int?, Never>) {
        guard !finished, (1...65535).contains(port), let port = NWEndpoint.Port(rawValue: UInt16(port)) else { continuation.resume(returning: nil); return }
        self.continuation = continuation
        let parameters: NWParameters
        if request.tls {
            let tls = NWProtocolTLS.Options()
            // Xray forwards encrypted bytes to the real destination. Validate its
            // certificate using that destination's name, not the loopback address.
            sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, request.host)
            sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, trust, complete in
                let secTrust = sec_trust_copy_ref(trust).takeRetainedValue()
                guard SecTrustSetPolicies(secTrust, SecPolicyCreateSSL(true, request.host as CFString)) == errSecSuccess else {
                    complete(false)
                    return
                }
                complete(SecTrustEvaluateWithError(secTrust, nil))
            }, queue)
            parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        } else { parameters = .tcp }
        parameters.requiredInterface = interface
        let connection = NWConnection(host: NWEndpoint.Host(host), port: port, using: parameters)
        self.connection = connection
        connection.stateUpdateHandler = { [weak self] state in
            guard let self, !self.finished else { return }
            switch state {
            case .ready:
                connection.send(content: request.data, completion: .contentProcessed { error in
                    if error != nil { self.finish(nil) } else { self.read(connection, expectedStatusCode: request.expectedStatusCode) }
                })
            case .failed, .cancelled: self.finish(nil)
            default: break
            }
        }
        // Exclude queue/setup work; include the actual connection and HTTP reply.
        started = ProcessInfo.processInfo.systemUptime
        connection.start(queue: queue)
        queue.asyncAfter(deadline: .now() + timeout) { self.finish(nil) }
    }

    private func read(_ connection: NWConnection, expectedStatusCode: Int?) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [weak self] data, _, complete, error in
            guard let self, !self.finished else { return }
            if let data { self.response.append(data) }
            if let successful = HTTPProbeRequest.successfulResponse(self.response, expectedStatusCode: expectedStatusCode) {
                let elapsed = max(1, Int((ProcessInfo.processInfo.systemUptime - self.started) * 1000))
                self.finish(successful ? elapsed : nil)
            } else if complete || error != nil { self.finish(nil) }
            else { self.read(connection, expectedStatusCode: expectedStatusCode) }
        }
    }

    private func finish(_ result: Int?) {
        guard !finished else { return }
        finished = true
        connection?.cancel(); connection = nil
        let reply = continuation; continuation = nil
        reply?.resume(returning: result)
    }
}
