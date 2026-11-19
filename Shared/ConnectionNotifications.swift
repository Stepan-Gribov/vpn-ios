import Foundation
import UserNotifications

enum ConnectionNotifications {
    private static let identifier = "kindlyvpn.connection"
    static let category = "VPN_RECOVERY"
    static let retryAction = "VPN_RETRY"
    static let actionReceived = Notification.Name("KindlyVPNRecoveryAction")

    static func requestAuthorization() {
        let center = UNUserNotificationCenter.current()
        let retry = UNNotificationAction(identifier: retryAction, title: "Retry", options: [.foreground])
        center.setNotificationCategories([UNNotificationCategory(identifier: category, actions: [retry], intentIdentifiers: [])])
        center.requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    static func post(title: String, body: String, retry: Bool = false, enabled: Bool) {
        guard enabled else { return }
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default
        if retry { content.categoryIdentifier = category }
        UNUserNotificationCenter.current().add(UNNotificationRequest(
            identifier: identifier, content: content, trigger: nil
        )) { error in
            if let error { RuntimeLog.write("Connection notification: \(error.localizedDescription)") }
        }
    }

    static func clear() {
        let center = UNUserNotificationCenter.current()
        center.removePendingNotificationRequests(withIdentifiers: [identifier])
        center.removeDeliveredNotifications(withIdentifiers: [identifier])
    }
}
