import SwiftUI
import UIKit
#if !targetEnvironment(macCatalyst)
import BackgroundTasks
#endif

@main
struct TnDtunApp: App {
    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var store: SimpleStore
    @StateObject private var panel: PanelManager
    @StateObject private var vpn: VPNManager
    @StateObject private var runtimeStore: AppStore
    #if !targetEnvironment(macCatalyst)
    @UIApplicationDelegateAdaptor(SubscriptionRefreshDelegate.self) private var refreshDelegate
    #endif

    init() {
        let isUITesting = ProcessInfo.processInfo.arguments.contains("--ui-testing")
        let initialStore: SimpleStore
        if isUITesting {
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
        let initialVPN = VPNManager(), initialRuntime = AppStore()
        _store = StateObject(wrappedValue: initialStore)
        _vpn = StateObject(wrappedValue: initialVPN)
        _runtimeStore = StateObject(wrappedValue: initialRuntime)
        let initialPanel: PanelManager
        #if DEBUG
        if isUITesting {
            initialPanel = PanelManager.forUITesting(store: initialStore)
        } else {
            initialPanel = Self.makePanel(store: initialStore)
        }
        #else
        initialPanel = Self.makePanel(store: initialStore)
        #endif
        _panel = StateObject(wrappedValue: initialPanel)
        #if !targetEnvironment(macCatalyst)
        SubscriptionRefreshDelegate.refresh = {
            guard !isUITesting, !Task.isCancelled else { return false }
            await initialPanel.prepareRuntime(initialRuntime, vpn: initialVPN)
            return await initialPanel.refreshDueSubscriptions()
        }
        #endif
    }

    private static func makePanel(store: SimpleStore) -> PanelManager {
        #if targetEnvironment(macCatalyst)
        PanelManager(store: store)
        #else
        PanelManager(store: store, scheduleBackground: SubscriptionRefreshDelegate.schedule)
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
                .onValueChange(of: scenePhase) { phase in
                    if phase != .active { panel.setForegroundActive(false) }
                }
                .task(id: scenePhase) {
                    guard scenePhase == .active else { return }
                    await panel.prepareRuntime(runtimeStore, vpn: vpn)
                    guard !Task.isCancelled else { return }
                    vpn.bind(store: runtimeStore)
                    panel.setForegroundActive(true)
                    await vpn.connectOnLaunchIfNeeded(store: store, runtime: runtimeStore)
                }
                .task {
                    #if targetEnvironment(macCatalyst)
                    for case let scene as UIWindowScene in UIApplication.shared.connectedScenes {
                        scene.sizeRestrictions?.minimumSize = CGSize(width: 500, height: 640)
                    }
                    #endif
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

#if !targetEnvironment(macCatalyst)
@MainActor
private final class SubscriptionRefreshDelegate: NSObject, UIApplicationDelegate {
    private static let identifier = (Bundle.main.bundleIdentifier ?? "") + ".subscription-refresh"
    private static var requestedDate: Date?
    private static var checkedSchedule = false
    static var refresh: (() async -> Bool)?

    func application(_ application: UIApplication, didFinishLaunchingWithOptions options: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        BGTaskScheduler.shared.register(forTaskWithIdentifier: Self.identifier, using: .main) { task in
            Task { @MainActor in
                Self.requestedDate = nil
                Self.checkedSchedule = false
                let work = Task { @MainActor in await Self.refresh?() ?? false }
                task.expirationHandler = { work.cancel() }
                let success = await work.value
                task.setTaskCompleted(success: success)
            }
        }
        return true
    }

    static func schedule(_ date: Date?) {
        guard !checkedSchedule || requestedDate != date else { return }
        checkedSchedule = true
        requestedDate = date
        guard let date else {
            BGTaskScheduler.shared.cancel(taskRequestWithIdentifier: identifier)
            return
        }
        let request = BGAppRefreshTaskRequest(identifier: identifier)
        request.earliestBeginDate = max(date, Date().addingTimeInterval(60))
        do { try BGTaskScheduler.shared.submit(request) }
        catch { checkedSchedule = false }
    }
}
#endif
