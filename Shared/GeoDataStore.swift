import Foundation

enum GeoDataStore {
    static func directory() throws -> URL {
        guard let container = AppGroup.containerURL else { throw CocoaError(.fileNoSuchFile) }
        let directory = container.appendingPathComponent("geo", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        for name in ["geoip", "geosite"] {
            let destination = directory.appendingPathComponent(name + ".dat")
            if !FileManager.default.fileExists(atPath: destination.path),
               let bundled = Bundle.main.url(forResource: name, withExtension: "dat") {
                try FileManager.default.copyItem(at: bundled, to: destination)
            }
        }
        return directory
    }

    static func install(_ file: URL, name: String) throws {
        guard name == (name as NSString).lastPathComponent, name.lowercased().hasSuffix(".dat") else { throw CocoaError(.fileWriteInvalidFileName) }
        let data = try Data(contentsOf: file, options: .mappedIfSafe)
        guard !data.isEmpty, !data.starts(with: Data("version https://git-lfs".utf8)),
              !String(decoding: data.prefix(64), as: UTF8.self).lowercased().contains("<html") else {
            throw CocoaError(.fileReadCorruptFile)
        }
        try data.write(to: directory().appendingPathComponent(name), options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }
}
