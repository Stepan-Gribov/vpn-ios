import Foundation

/// The extension owns totals so traffic continues to count while the app sleeps.
/// Speeds are measured from byte deltas and actual sampling intervals.
struct TrafficLedger {
    private(set) var uploaded: UInt64 = 0
    private(set) var downloaded: UInt64 = 0
    private(set) var uploadSpeed: Double = 0
    private(set) var downloadSpeed: Double = 0

    init(uploaded: UInt64 = 0, downloaded: UInt64 = 0) {
        self.uploaded = uploaded; self.downloaded = downloaded
    }

    mutating func record(sent: Int64, received: Int64, elapsed: TimeInterval) {
        let up = UInt64(max(0, sent)); let down = UInt64(max(0, received))
        uploaded = adding(up, to: uploaded)
        downloaded = adding(down, to: downloaded)
        let interval = elapsed.isFinite && elapsed > 0 ? elapsed : 1
        uploadSpeed = Double(up) / interval
        downloadSpeed = Double(down) / interval
    }

    private func adding(_ delta: UInt64, to total: UInt64) -> UInt64 {
        let result = total.addingReportingOverflow(delta)
        return result.overflow ? .max : result.partialValue
    }
}
