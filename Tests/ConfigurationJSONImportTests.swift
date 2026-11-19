import XCTest
@testable import TnDtun

final class ConfigurationJSONImportTests: XCTestCase {
    private let uuid = "9f774dc1-395b-4397-890a-123456789abc"
    private let key = String(repeating: "ab", count: 32)

    func testMinimumTURNReplacesConnectionFieldsAndKeepsIdentity() throws {
        var base = SimpleConfiguration()
        base.callLink = "https://vk.com/call/join/old"
        base.server = "203.0.113.99"
        let text = """
        {"mode":"turn","call_link":"https://vk.com/call/join/new","server":"203.0.113.10","vless_id":"\(uuid)"}
        """
        let result = try ConfigurationJSONImporter.apply(text, to: base).configuration
        XCTAssertEqual(result.id, base.id)
        XCTAssertEqual(result.callLink, "https://vk.com/call/join/new")
        XCTAssertEqual(result.server, "203.0.113.10:56010")
        XCTAssertEqual(result.vlessID, uuid)
        XCTAssertEqual(result.wrapKey, "")
        XCTAssertEqual(base.server, "203.0.113.99")
    }

    func testTURNAllowsNativeNamesAndOptionalWrapping() throws {
        let text = """
        {"vk_link":"https://vk.com/call/join/new","peer_addr":"[2001:db8::1]:443","uuid":"\(uuid)","wrap_key":"\(key.uppercased())"}
        """
        let result = try ConfigurationJSONImporter.apply(text, to: SimpleConfiguration()).configuration
        XCTAssertEqual(result.wrapKey, key)
        XCTAssertEqual(result.server, "[2001:db8::1]:443")
    }

    func testMinimumDNSKeepsCarrierResolverAndLocalPreferences() throws {
        var base = SimpleConfiguration(); base.mode = .dns
        base.dns.resolver = "203.0.113.53:53"
        base.dns.useWiFiResolver = true; base.dns.wifiResolver = "8.8.8.8"
        base.dns.sessionCount = 8
        base.dns.sshPassword = "old credential"
        let result = try ConfigurationJSONImporter.apply(
            "{\"mode\":\"dns\",\"domain\":\"Tunnel.Example.COM.\",\"public_key\":\"\(key)\"}", to: base)
        XCTAssertFalse(result.includesResolver)
        XCTAssertEqual(result.configuration.id, base.id)
        XCTAssertEqual(result.configuration.dns.domain, "tunnel.example.com")
        XCTAssertEqual(result.configuration.dns.resolver, base.dns.resolver)
        XCTAssertEqual(result.configuration.dns.wifiResolver, "8.8.8.8:53")
        XCTAssertTrue(result.configuration.dns.useWiFiResolver)
        XCTAssertEqual(result.configuration.dns.sessionCount, 8)
        XCTAssertEqual(result.configuration.dns.tunnelType, "socks5")
        XCTAssertEqual(result.configuration.dns.sshPassword, "")
    }

    func testNestedDNSAndSSHPasswordAreImportedWithoutTrimmingSecrets() throws {
        var base = SimpleConfiguration(); base.mode = .dns
        let text = """
        {"mode":"dns","dns":{"domain":"tunnel.example.com","publicKey":"\(key)","tunnelType":"SSH","resolver":"2001:4860:4860::8888","sshUsername":"test","sshPassword":" password ","sshHostKey":"SHA256:test-fingerprint"}}
        """
        let result = try ConfigurationJSONImporter.apply(text, to: base)
        XCTAssertTrue(result.includesResolver)
        XCTAssertEqual(result.configuration.dns.resolver, "[2001:4860:4860::8888]:53")
        XCTAssertEqual(result.configuration.dns.sshPassword, " password ")
        XCTAssertEqual(result.configuration.dns.tunnelType, "ssh")
        let payload = try result.configuration.dns.runtimePayload()
        XCTAssertTrue(String(decoding: payload, as: UTF8.self).contains(" password "))
    }

    func testMalformedWrongModeMissingFieldsAndInvalidCredentialsAreRejectedAtomically() {
        let base = SimpleConfiguration()
        let cases = [
            "not json", "[]", "null", "{}", "{\"mode\":\"dns\"}",
            "{\"mode\":\"unknown\"}",
            "{\"call_link\":123}",
            "{\"call_link\":\"https://vk.com/call/join/new\",\"server\":\"203.0.113.10\",\"vless_id\":\"bad UUID\"}",
            "{\"call_link\":\"https://vk.com/call/join/new\",\"server\":\"203.0.113.10\",\"vless_id\":\"\(uuid)\",\"wrap_key\":\"bad key\"}",
            "{\"call_link\":\"one\",\"callLink\":\"another\"}",
            String(repeating: " ", count: 65_537)
        ]
        for text in cases { XCTAssertThrowsError(try ConfigurationJSONImporter.apply(text, to: base)) }
        XCTAssertEqual(base.callLink, "")
        XCTAssertEqual(base.vlessID, "")
        var dns = base; dns.mode = .dns
        XCTAssertThrowsError(try ConfigurationJSONImporter.apply("{\"dns\":[]}", to: dns))
        XCTAssertThrowsError(try ConfigurationJSONImporter.apply(
            "{\"domain\":\"tunnel.example.com\",\"public_key\":\"\(key)\",\"tunnel_type\":\"ssh\"}", to: dns))
    }
}
