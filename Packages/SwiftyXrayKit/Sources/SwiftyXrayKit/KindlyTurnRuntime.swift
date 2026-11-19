import Foundation
import LibXray

/// TURN helper exported from the same Go runtime as Xray.
public enum KindlyTurnRuntime {
    public static func start(configurationJSON: String) -> Int32 {
        LibXrayKindlyTurnStart(configurationJSON)
    }

    public static func stop() {
        LibXrayKindlyTurnStop()
    }

    public static func statusData() -> Data {
        Data(LibXrayKindlyTurnStatus().utf8)
    }

    /// Negotiation only. A real route check is still required after refresh.
    public static var supportsConnectionResume: Bool { LibXrayKindlyTurnSupportsResume() }

    public static func refreshNetwork() -> Bool { LibXrayKindlyTurnRefreshNetwork() }

    public static func validateRecovery(configurationJSON: String) -> Bool {
        LibXrayKindlyRecoveryValidate(configurationJSON).isEmpty
    }
}
