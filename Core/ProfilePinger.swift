import Foundation
import SwiftyXrayKit

/// Serial, isolated Xray instances in the app process; the active extension is unaffected.
@MainActor
enum ProfilePinger {
    private static var pending: Task<Int?, Never>?
    private static var jobs = [UUID: Task<Int?, Never>]()

    static func cancelAll() async {
        let current = Array(jobs.values)
        for job in current { job.cancel() }
        for job in current { _ = await job.value }
    }

    static func ping(_ profile: VPNProfile, settings: AppSettings, turnReady: Bool = false) async -> Int? {
        // A TURN row needs the existing relay helper. Never pretend a TCP dial to its
        // UDP peer is a measurement of the VPN or initiate a VK call during Smart Connect.
        guard profile.connectionValidationError == nil, !profile.isTURN || turnReady else { return nil }
        let previous = pending
        let id = UUID()
        let job = Task { @MainActor in
            _ = await previous?.value
            return await measure(profile, settings: settings)
        }
        pending = job
        jobs[id] = job
        defer { jobs.removeValue(forKey: id) }
        return await withTaskCancellationHandler { await job.value } onCancel: { job.cancel() }
    }

    private static func measure(_ profile: VPNProfile, settings: AppSettings) async -> Int? {
        guard !Task.isCancelled, let request = HTTPProbeRequest(settings.connectivityTestURL) else { return nil }
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("probe-\(UUID().uuidString)")
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: directory) }
            guard let port = try SwiftyXray.getFreePorts(1).first,
                  let config = XrayConfigurationBuilder.probeConfiguration(profile: profile, settings: settings, localPort: port, request: request) else { return nil }
            let file = directory.appendingPathComponent("config.json")
            try config.write(to: file, atomically: true, encoding: .utf8)
            let dataDir = (try? GeoDataStore.directory()) ?? Bundle.main.resourceURL ?? Bundle.main.bundleURL
            defer { try? SwiftyXray.stop() }
            try SwiftyXray.run(dataDir: dataDir.path, configPath: file.path)
            return await ForwardedProbe.measure(port: port, request: request)
        } catch {
            RuntimeLog.write("Profile probe failed: \(error.localizedDescription)")
            return nil
        }
    }
}
