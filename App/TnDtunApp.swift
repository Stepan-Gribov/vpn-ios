import SwiftUI
#if targetEnvironment(macCatalyst)
import UIKit
#endif

@main
struct TnDtunApp: App {
    @StateObject private var store: SimpleStore
    @StateObject private var panel: PanelManager
    @StateObject private var vpn = VPNManager()
    @StateObject private var runtimeStore = AppStore()

    init() {
        let initialStore: SimpleStore
        if ProcessInfo.processInfo.arguments.contains("--ui-testing") {
            let file = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
                .appendingPathComponent("ui-testing/configurations.json")
            let defaults = UserDefaults(suiteName: "simple.ui-testing")!
            if ProcessInfo.processInfo.arguments.contains("--reset-ui-testing") {
                try? FileManager.default.removeItem(at: file.deletingLastPathComponent())
                defaults.removePersistentDomain(forName: "simple.ui-testing")
            }
            initialStore = SimpleStore(fileURL: file, defaults: defaults)
        } else {
            initialStore = SimpleStore()
        }
        _store = StateObject(wrappedValue: initialStore)
        #if DEBUG
        if ProcessInfo.processInfo.arguments.contains("--ui-testing") {
            _panel = StateObject(wrappedValue: PanelManager.forUITesting(store: initialStore))
        } else {
            _panel = StateObject(wrappedValue: PanelManager(store: initialStore))
        }
        #else
        _panel = StateObject(wrappedValue: PanelManager(store: initialStore))
        #endif
    }

    var body: some Scene {
        WindowGroup {
            MainView()
                .environmentObject(store)
                .environmentObject(panel)
                .environmentObject(vpn)
                .environmentObject(runtimeStore)
                .tint(Color(red: 0.12, green: 0.31, blue: 0.93))
                .preferredColorScheme(.light)
                .onOpenURL { panel.receive($0) }
                .task {
                    #if targetEnvironment(macCatalyst)
                    for case let scene as UIWindowScene in UIApplication.shared.connectedScenes {
                        scene.sizeRestrictions?.minimumSize = CGSize(width: 500, height: 640)
                    }
                    #endif
                    panel.attach(runtime: runtimeStore, vpn: vpn)
                    runtimeStore.applyPanelDNS(store.applicationDNSServers)
                    await vpn.load()
                    let selected = (vpn.tunnelIsActive ? vpn.connectedProfileID : nil) ?? store.selectedProfileID ?? AppGroup.defaults.string(forKey: AppGroup.activeProfileKey)
                    runtimeStore.restoreSelection(store.availableConfigurations, profileID: selected)
                    runtimeStore.applySplitTunneling(store.splitTunneling)
                    runtimeStore.applySplitOptions(amnezia: store.amneziaSplitEnabled, minutes: store.fullTunnelMinutes)
                    runtimeStore.applyAutomation(autoCaptcha: store.autoCaptcha, autoRecovery: store.autoRecovery, turnCheckInterval: store.turnCheckInterval)
                    vpn.bind(store: runtimeStore)
                    await vpn.connectOnLaunchIfNeeded(store: store, runtime: runtimeStore)
                    #if DEBUG
                    if ProcessInfo.processInfo.arguments.contains("--device-subscription-check") {
                        let file = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent("subscription-device-check.json")
                        if let data = try? Data(contentsOf: file),
                           let values = try? JSONSerialization.jsonObject(with: data) as? [String: String],
                           let code = values["activation_code"] {
                            try? FileManager.default.removeItem(at: file)
                            panel.updateActivationText(code); panel.showingSubscription = true
                        }
                    }
                    #endif
                }
        }
    }
}
