import Foundation
import CryptoKit

/// An authenticated, fixed-size access index is part of the SAME atomic vault
/// file. The extension reads one record, never every profile/large split list.
/// This keeps a valid multi-megabyte package out of its small memory budget.
enum PanelAccessIndex {
    static let magic = Data("TNDPV002".utf8)
    static let recordSize = 109 // lookup SHA256 (32) + GCM nonce/plaintext/tag (77)
    static let maximumFileSize = 128 * 1024 * 1024
    enum Format: Error { case legacy }
    struct Record {
        var generation: Int64
        var expiry: Int64
        var allowed: Bool
        var digest: Data
        func permits(_ grant: PanelAccessGrant, now: Int64) -> Bool {
            allowed && now < expiry && generation == grant.generation && digest == PanelAccessIndex.digest(grant.credentialDigest)
        }
    }
    static func lookupKey(_ grant: PanelAccessGrant) -> Data { lookupKey(subscriptionID: grant.subscriptionID, profileID: grant.profileID) }
    private static func lookupKey(subscriptionID: String, profileID: String) -> Data {
        Data(SHA256.hash(data: Data(subscriptionID.utf8) + Data([0]) + Data(profileID.utf8)))
    }
    private static func aad(_ lookup: Data) -> Data { Data("TnDtun-panel-access-v2".utf8) + lookup }
    private static func integer(_ value: Int64) -> Data { var number = UInt64(bitPattern: value).bigEndian; return withUnsafeBytes(of: &number) { Data($0) } }
    private static func decodeInteger(_ bytes: Data.SubSequence) -> Int64 { Int64(bitPattern: bytes.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }) }
    static func digest(_ value: String) -> Data {
        let chars = Array(value.utf8)
        guard chars.count == 64 else { return Data() }
        func nibble(_ byte: UInt8) -> UInt8 { byte <= 57 ? byte &- 48 : byte &- 87 }
        return Data(stride(from: 0, to: 64, by: 2).map { (nibble(chars[$0]) << 4) | nibble(chars[$0 + 1]) })
    }
    static func seal(_ state: PanelVaultState, clear: Data, key: SymmetricKey) throws -> Data {
        var rows: [(Data, Data)] = []
        for sub in state.subscriptions {
            for profile in sub.package.profiles {
                let lookup = lookupKey(subscriptionID: sub.id, profileID: profile.id)
                let plain = integer(profile.generation) + integer(sub.package.expiresAt ?? Int64.max) + Data([sub.package.status == "active" ? 1 : 0]) + digest(profile.credentialDigest)
                guard plain.count == 49 else { throw PanelFailure("Invalid subscription access index.") }
                let sealed = try AES.GCM.seal(plain, using: key, authenticating: aad(lookup))
                guard let record = sealed.combined, record.count == 77 else { throw PanelFailure("Subscription access could not be encrypted.") }
                rows.append((lookup, lookup + record))
            }
        }
        rows.sort { $0.0.lexicographicallyPrecedes($1.0) }
        guard rows.count <= 1_000_000 else { throw PanelFailure("Too many subscription access records.") }
        var count = UInt32(rows.count).bigEndian
        var header = magic + withUnsafeBytes(of: &count) { Data($0) }
        for row in rows { header.append(row.1) }
        let sealed = try AES.GCM.seal(clear, using: key, authenticating: stateAAD(header))
        guard let body = sealed.combined else { throw PanelFailure("Subscription settings could not be encrypted.") }
        let result = header + body
        guard result.count <= maximumFileSize else { throw PanelFailure("Subscription storage is too large.") }
        return result
    }
    static func open(_ bytes: Data, key: SymmetricKey) throws -> Data {
        guard bytes.starts(with: magic) else {
            // Read the first development format, then migrate on the next commit.
            return try AES.GCM.open(AES.GCM.SealedBox(combined: bytes), using: key, authenticating: Data("TnDtun-panel-state-v1".utf8))
        }
        guard bytes.count >= 12 else { throw PanelFailure("Incomplete subscription storage.") }
        let count = Int(decodeInteger(bytes[8..<12]))
        let offset = 12 + count * recordSize
        guard count <= 1_000_000, offset <= bytes.count - 28 else { throw PanelFailure("Incomplete subscription storage.") }
        return try AES.GCM.open(AES.GCM.SealedBox(combined: bytes.subdata(in: offset..<bytes.count)), using: key, authenticating: stateAAD(bytes.prefix(offset)))
    }
    private static func stateAAD(_ header: Data) -> Data { Data("TnDtun-panel-state-v2".utf8) + Data(SHA256.hash(data: header)) }
    static func lookup(_ grant: PanelAccessGrant, at url: URL, key: () throws -> SymmetricKey) throws -> Record? {
        let file = try FileHandle(forReadingFrom: url); defer { try? file.close() }
        let size = try file.seekToEnd(); try file.seek(toOffset: 0)
        guard size <= maximumFileSize else { throw PanelFailure("Subscription storage is too large.") }
        let prefix = try file.read(upToCount: 12) ?? Data()
        guard prefix.starts(with: magic) else { throw Format.legacy }
        guard prefix.count == 12 else { throw PanelFailure("Incomplete subscription access index.") }
        let count = Int(decodeInteger(prefix[8..<12]))
        guard count <= 1_000_000, UInt64(12 + count * recordSize + 28) <= size else { throw PanelFailure("Incomplete subscription access index.") }
        let wanted = lookupKey(grant)
        var low = 0, high = count
        while low < high {
            let mid = low + (high - low) / 2
            try file.seek(toOffset: UInt64(12 + mid * recordSize))
            guard let row = try file.read(upToCount: recordSize), row.count == recordSize else { throw PanelFailure("Incomplete subscription access record.") }
            let found = row.prefix(32)
            if found == wanted {
                let plain = try AES.GCM.open(AES.GCM.SealedBox(combined: row.dropFirst(32)), using: key(), authenticating: aad(wanted))
                guard plain.count == 49 else { throw PanelFailure("Invalid subscription access record.") }
                return Record(generation: decodeInteger(plain[0..<8]), expiry: decodeInteger(plain[8..<16]), allowed: plain[16] == 1, digest: plain.subdata(in: 17..<49))
            }
            if found.lexicographicallyPrecedes(wanted) { low = mid + 1 } else { high = mid }
        }
        return nil
    }
}
