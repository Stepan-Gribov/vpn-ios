import Foundation
import os

enum RuntimeLog {
    enum Filter: String, CaseIterable, Identifiable {
        case all = "All", info = "Info+", warning = "Warn+", error = "Errors"
        var id: String { rawValue }
        func includes(_ entry: String) -> Bool {
            let value = entry.lowercased()
            let isError = ["[error]", "failed", "failure", "ошибка", "ошибк", "не удалось"].contains(where: value.contains)
            let isWarning = isError || value.contains("[warning]") || value.contains("[warn]")
            switch self {
            case .all: return true
            case .info: return !value.contains("[debug]")
            case .warning: return isWarning
            case .error: return isError
            }
        }
    }

    static var xrayLogURL: URL? { AppGroup.containerURL?.appendingPathComponent("xray.log") }
    private static let logger = Logger(subsystem: "com.kindlyvpn.ios", category: "runtime")
    private static let maxEntries = 300

    static func write(_ message: String) {
        logger.info("\(message, privacy: .public)")
        var entries = AppGroup.defaults.stringArray(forKey: AppGroup.logsKey) ?? []
        let formatter = ISO8601DateFormatter()
        entries.append("\(formatter.string(from: Date()))  \(message)")
        if entries.count > maxEntries { entries.removeFirst(entries.count - maxEntries) }
        AppGroup.defaults.set(entries, forKey: AppGroup.logsKey)
        AppGroup.defaults.synchronize()
    }

    static func entries() -> [String] {
        var entries = AppGroup.defaults.stringArray(forKey: AppGroup.logsKey) ?? []
        if let url = xrayLogURL, let file = try? FileHandle(forReadingFrom: url) {
            defer { try? file.close() }
            if let length = try? file.seekToEnd() {
                try? file.seek(toOffset: length > 256_000 ? length - 256_000 : 0)
                if let data = try? file.readToEnd(), let text = String(data: data, encoding: .utf8) {
                    entries.append(contentsOf: text.components(separatedBy: .newlines).filter { !$0.isEmpty }.suffix(maxEntries))
                }
            }
        }
        return entries
    }

    static func clear() {
        AppGroup.defaults.removeObject(forKey: AppGroup.logsKey)
        if let url = xrayLogURL, let file = try? FileHandle(forWritingTo: url) {
            try? file.truncate(atOffset: 0); try? file.close()
        }
    }
}
