import Foundation

struct PanelFailure: LocalizedError, Equatable {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

/// Strict JSON before Codable: preserves numeric types and rejects duplicate
/// (including escaped) names, invalid UTF-8, trailing input and excessive depth.
indirect enum PanelJSON: Equatable {
    case object([String: PanelJSON]), array([PanelJSON]), string(String), number(String), bool(Bool), null

    static func parse(_ data: Data, limit: Int) throws -> Self {
        guard data.count <= limit, String(data: data, encoding: .utf8) != nil else {
            throw PanelFailure("The service response is too large or contains invalid text.")
        }
        var parser = Parser(bytes: Array(data))
        let result = try parser.value(depth: 0)
        parser.space()
        guard parser.index == parser.bytes.count else { throw PanelFailure("The service returned invalid JSON.") }
        return result
    }

    var object: [String: PanelJSON] {
        get throws { guard case .object(let result) = self else { throw PanelFailure("Invalid response structure.") }; return result }
    }
    func field(_ name: String) throws -> PanelJSON {
        guard let result = try object[name] else { throw PanelFailure("Missing service field: \(name).") }; return result
    }
    func text(_ maximum: Int = 200, lines: Bool = false) throws -> String {
        guard case .string(let result) = self, result.utf16.count <= maximum,
              !result.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) && !(lines && "\n\r\t".unicodeScalars.contains($0)) }) else {
            throw PanelFailure("Invalid text field in service response.")
        }
        return result
    }
    var integer: Int64 {
        get throws {
            guard case .number(let raw) = self, !raw.contains(where: { ".eE".contains($0) }), let result = Int64(raw) else {
                throw PanelFailure("Invalid integer in service response.")
            }; return result
        }
    }
    var boolean: Bool {
        get throws { guard case .bool(let result) = self else { throw PanelFailure("Invalid switch in service response.") }; return result }
    }
    var array: [PanelJSON] {
        get throws { guard case .array(let result) = self else { throw PanelFailure("Invalid list in service response.") }; return result }
    }
    var isNull: Bool { self == .null }
    func encoded() throws -> Data {
        switch self {
        case .object(let fields):
            var result = Data("{".utf8)
            for (index, name) in fields.keys.sorted().enumerated() {
                if index > 0 { result.append(44) }
                result.append(try JSONEncoder().encode(name)); result.append(58)
                result.append(try fields[name]!.encoded())
            }
            result.append(125); return result
        case .array(let elements):
            var result = Data("[".utf8)
            for (index, value) in elements.enumerated() { if index > 0 { result.append(44) }; result.append(try value.encoded()) }
            result.append(93); return result
        case .string(let string): return try JSONEncoder().encode(string)
        case .number(let number): return Data(number.utf8)
        case .bool(let flag): return Data((flag ? "true" : "false").utf8)
        case .null: return Data("null".utf8)
        }
    }

    private struct Parser {
        let bytes: [UInt8]
        var index = 0
        mutating func space() { while index < bytes.count && [9, 10, 13, 32].contains(bytes[index]) { index += 1 } }
        mutating func take(_ byte: UInt8) -> Bool {
            space(); guard index < bytes.count && bytes[index] == byte else { return false }; index += 1; return true
        }
        mutating func string() throws -> String {
            space(); let start = index
            guard index < bytes.count && bytes[index] == 34 else { throw malformed() }; index += 1
            while index < bytes.count {
                let byte = bytes[index]; index += 1
                if byte == 34 {
                    do { return try JSONDecoder().decode(String.self, from: Data(bytes[start..<index])) }
                    catch { throw malformed() }
                }
                if byte == 92 {
                    guard index < bytes.count else { throw malformed() }
                    if bytes[index] == 117 {
                        guard index + 4 < bytes.count else { throw malformed() }
                        index += 5
                    } else { index += 1 }
                } else if byte < 32 { throw malformed() }
            }
            throw malformed()
        }
        mutating func value(depth: Int) throws -> PanelJSON {
            space(); guard index < bytes.count else { throw malformed() }
            switch bytes[index] {
            case 123:
                guard depth < 32 else { throw PanelFailure("The service JSON is too deeply nested.") }
                index += 1; var fields: [String: PanelJSON] = [:]
                if take(125) { return .object(fields) }
                repeat {
                    let name = try string()
                    guard fields[name] == nil, take(58) else { throw PanelFailure("Duplicate or invalid JSON field.") }
                    fields[name] = try value(depth: depth + 1)
                    if take(125) { return .object(fields) }
                    guard take(44) else { throw malformed() }
                } while true
            case 91:
                guard depth < 32 else { throw PanelFailure("The service JSON is too deeply nested.") }
                index += 1; var elements: [PanelJSON] = []
                if take(93) { return .array(elements) }
                repeat {
                    elements.append(try value(depth: depth + 1))
                    if take(93) { return .array(elements) }
                    guard take(44) else { throw malformed() }
                } while true
            case 34: return .string(try string())
            case 116: try literal("true"); return .bool(true)
            case 102: try literal("false"); return .bool(false)
            case 110: try literal("null"); return .null
            default:
                let start = index
                if bytes[index] == 45 { index += 1 }
                guard index < bytes.count else { throw malformed() }
                if bytes[index] == 48 { index += 1 }
                else {
                    guard (49...57).contains(bytes[index]) else { throw malformed() }
                    while index < bytes.count && (48...57).contains(bytes[index]) { index += 1 }
                }
                if index < bytes.count && bytes[index] == 46 {
                    index += 1; let digits = index
                    while index < bytes.count && (48...57).contains(bytes[index]) { index += 1 }
                    guard index > digits else { throw malformed() }
                }
                if index < bytes.count && (bytes[index] == 101 || bytes[index] == 69) {
                    index += 1
                    if index < bytes.count && (bytes[index] == 43 || bytes[index] == 45) { index += 1 }
                    let digits = index
                    while index < bytes.count && (48...57).contains(bytes[index]) { index += 1 }
                    guard index > digits else { throw malformed() }
                }
                return .number(String(decoding: bytes[start..<index], as: UTF8.self))
            }
        }
        mutating func literal(_ text: String) throws {
            let expected = Array(text.utf8)
            guard index + expected.count <= bytes.count, Array(bytes[index..<index + expected.count]) == expected else { throw malformed() }
            index += expected.count
        }
        func malformed() -> PanelFailure { PanelFailure("The service returned invalid JSON.") }
    }
}
