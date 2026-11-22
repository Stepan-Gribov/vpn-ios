import XCTest
import UIKit

final class TnDtunUITests: XCTestCase {
    private var app: XCUIApplication!
    override func setUp() {
        continueAfterFailure = false
        app = XCUIApplication()
        if ProcessInfo.processInfo.environment["TNDTUN_DEVICE_SUBSCRIPTION_CHECK"] == "1" {
            app.launchArguments = ["--device-subscription-check"]
        } else if ProcessInfo.processInfo.environment["TNDTUN_DEVICE_AMNEZIA_BACKGROUND_CHECK"] == "1" {
            app.launchArguments = ["--device-amnezia-background-check"]
        } else {
            app.launchArguments = ProcessInfo.processInfo.environment["TNDTUN_DEVICE_BACKGROUND_CHECK"] == "1"
                ? ["--device-turn-background-check"] : ["--ui-testing", "--reset-ui-testing"]
        }
        app.launch()
    }

    func testBuiltInDNSIsVisibleAndHasNoEditOrDeleteMenu() {
        app.segmentedControls["modePicker"].buttons["DNS tunnel"].tap()
        XCTAssertTrue(app.buttons["connect_tndtun.builtin.dns.v1"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.images["builtInDNSLock"].exists)
        XCTAssertFalse(app.buttons["settings_tndtun.builtin.dns.v1"].exists)
        capture("built-in-dns-profile")
        app.buttons["addConfiguration"].tap()
        XCTAssertTrue(app.buttons["saveConfiguration"].waitForExistence(timeout: 5))
    }

    @MainActor func testPhysicalSubscriptionActivationFromPrivateFixture() async throws {
        #if targetEnvironment(macCatalyst)
        throw XCTSkip("Host Mac VPN must remain unchanged.")
        #else
        guard ProcessInfo.processInfo.environment["TNDTUN_DEVICE_SUBSCRIPTION_CHECK"] == "1" else { throw XCTSkip("Explicit device opt-in required.") }
        let field = app.descendants(matching: .any).matching(identifier: "activationInput").firstMatch
        XCTAssertTrue(field.waitForExistence(timeout: 15))
        let activate = app.buttons["activateAccess"]
        XCTAssertTrue(activate.isEnabled); activate.tap()
        let deadline = Date().addingTimeInterval(210)
        let success = app.staticTexts["subscriptionAdded"]
        while Date() < deadline {
            if app.staticTexts["subscriptionError"].exists { XCTFail("Subscription activation reported an error; inspect the private device report."); return }
            if success.exists { break }
            try await Task.sleep(for: .milliseconds(500))
        }
        XCTAssertTrue(success.exists, "Activation did not complete before the deadline")
        XCTAssertFalse(field.exists, "Do not capture the private subscription key")
        capture("device-subscription-activated")
        app.buttons["subscriptionAddedDone"].tap()
        app.buttons["openSubscription"].tap()
        let refresh = app.buttons["Refresh subscription"]
        XCTAssertTrue(refresh.waitForExistence(timeout: 5)); refresh.tap()
        let refreshed = expectation(for: NSPredicate(format: "enabled == true"), evaluatedWith: refresh)
        await fulfillment(of: [refreshed], timeout: 210)
        XCTAssertFalse(app.staticTexts["subscriptionError"].exists)
        XCTAssertTrue(app.staticTexts.matching(NSPredicate(format: "label CONTAINS %@", "Access active")).firstMatch.exists)
        capture("device-subscription-refreshed")
        app.buttons["Done"].tap()
        app.segmentedControls["modePicker"].buttons["DNS tunnel"].tap()
        XCTAssertTrue(app.buttons["connect_tndtun.builtin.dns.v1"].exists)
        capture("device-built-in-dns")
        #endif
    }

    @MainActor func testPhysicalAssignedSubscriptionProfileTransfersSystemHTTPS() async throws {
        #if targetEnvironment(simulator) || targetEnvironment(macCatalyst)
        throw XCTSkip("Requires an authorized physical iPad.")
        #else
        guard ProcessInfo.processInfo.environment["TNDTUN_DEVICE_SUBSCRIPTION_CHECK"] == "1",
              let id = ProcessInfo.processInfo.environment["TNDTUN_DEVICE_SUBSCRIPTION_PROFILE"] else { throw XCTSkip("Explicit profile opt-in required.") }
        let dnsMode = ProcessInfo.processInfo.environment["TNDTUN_DEVICE_SUBSCRIPTION_MODE"] == "dns"
        app.segmentedControls["modePicker"].buttons[dnsMode ? "DNS tunnel" : "Amnezia"].tap()
        let profile = app.buttons["connect_" + id]
        XCTAssertTrue(profile.waitForExistence(timeout: 10))
        if !profile.label.hasPrefix("Disconnect ") { profile.tap() }
        let selected = expectation(for: NSPredicate(format: "label BEGINSWITH %@", "Disconnect "), evaluatedWith: profile)
        await fulfillment(of: [selected], timeout: 180)
        let status = app.staticTexts["connectionStatus"]
        let ready = expectation(for: NSPredicate(format: "label == %@", "Connected"), evaluatedWith: status)
        await fulfillment(of: [ready], timeout: 180)
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = dnsMode ? 40 : 20; config.timeoutIntervalForResource = dnsMode ? 45 : 25
        let session = URLSession(configuration: config); defer { session.invalidateAndCancel() }
        let addresses = dnsMode ? ["https://www.gstatic.com/generate_204", "https://1.1.1.1/cdn-cgi/trace"] : ["https://www.gstatic.com/generate_204", "https://www.youtube.com/", "https://speed.cloudflare.com/__down?bytes=1048576"]
        for address in addresses {
            let (data, response) = try await session.data(from: URL(string: address)!)
            let code = (response as? HTTPURLResponse)?.statusCode ?? 0
            XCTAssertTrue((200..<400).contains(code))
            if address.contains("bytes=") { XCTAssertGreaterThanOrEqual(data.count, 1_048_576) }
            print("Assigned subscription profile system HTTPS: \(URL(string: address)!.host!), status=\(code), bytes=\(data.count)")
        }
        capture("device-subscription-connected")
        #endif
    }

    @MainActor func testPhysicalAmneziaRecoversPacketFlowWithContainingAppTerminated() async throws {
        #if targetEnvironment(simulator) || targetEnvironment(macCatalyst)
        throw XCTSkip("Requires a physical device and an existing authorized Amnezia profile.")
        #else
        guard ProcessInfo.processInfo.environment["TNDTUN_DEVICE_AMNEZIA_BACKGROUND_CHECK"] == "1" else {
            throw XCTSkip("Opt in with TNDTUN_DEVICE_AMNEZIA_BACKGROUND_CHECK=1.")
        }
        let connected = app.staticTexts["connectionStatus"]
        if connected.label != "Connected" {
            app.segmentedControls["modePicker"].buttons["Amnezia"].tap()
            let profile = app.buttons.matching(NSPredicate(format: "identifier BEGINSWITH 'connect_'")).firstMatch
            XCTAssertTrue(profile.waitForExistence(timeout: 10)); profile.tap()
        }
        let established = expectation(for: NSPredicate(format: "label == %@", "Connected"), evaluatedWith: connected)
        await fulfillment(of: [established], timeout: 120)
        try await Task.sleep(for: .seconds(2)) // Allow the provider to acknowledge the delayed fault.
        XCUIDevice.shared.press(.home)
        app.terminate()
        try await Task.sleep(for: .seconds(45))
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 20; config.timeoutIntervalForResource = 25
        let session = URLSession(configuration: config)
        defer { session.invalidateAndCancel() }
        for raw in ["https://www.gstatic.com/generate_204", "https://www.youtube.com/", "https://speed.cloudflare.com/__down?bytes=1048576"] {
            let (data, response) = try await session.data(from: URL(string: raw)!)
            let status = try XCTUnwrap(response as? HTTPURLResponse).statusCode
            XCTAssertTrue((200..<400).contains(status), "Real system traffic failed after background recovery: \(raw)")
            if raw.contains("bytes=") { XCTAssertGreaterThanOrEqual(data.count, 1_048_576) }
            print("Amnezia background system HTTPS: \(URL(string: raw)!.host!), status=\(status), bytes=\(data.count)")
        }
        XCTAssertNotEqual(app.state, .runningForeground, "Recovery must not require opening the app")
        #endif
    }

    func testPhysicalTURNRecoversWithContainingAppTerminated() throws {
        #if targetEnvironment(simulator) || targetEnvironment(macCatalyst)
        throw XCTSkip("Requires a physical device and an existing working TURN profile.")
        #else
        guard ProcessInfo.processInfo.environment["TNDTUN_DEVICE_BACKGROUND_CHECK"] == "1" else {
            throw XCTSkip("Opt in with TNDTUN_DEVICE_BACKGROUND_CHECK=1; reconnects the saved TURN profile.")
        }
        let connected = app.staticTexts["connectionStatus"]
        if connected.label != "Connected" {
            app.segmentedControls["modePicker"].buttons["TURN proxy"].tap()
            let profile = app.buttons.matching(NSPredicate(format: "identifier BEGINSWITH 'connect_'")).firstMatch
            XCTAssertTrue(profile.waitForExistence(timeout: 10)); profile.tap()
        }
        expectation(for: NSPredicate(format: "label == %@", "Connected"), evaluatedWith: connected)
        waitForExpectations(timeout: 240)
        // Leave time for the provider to acknowledge the diagnostic message;
        // the delayed failure is generated by the extension, not the app.
        Thread.sleep(forTimeInterval: 2)
        XCUIDevice.shared.press(.home)
        app.terminate()
        Thread.sleep(forTimeInterval: 60)
        // The CLI harness inspects the provider's shared log while this app is
        // still terminated. Do not reopen it to make a recovery appear to pass.
        #endif
    }

    func testConnectionGuideSwipesButtonsAndDismissal() {
        let help = app.buttons["connectionGuide"]
        XCTAssertTrue(help.waitForExistence(timeout: 5))
        capture("guide-main-question-button")
        help.tap()
        let indicator = app.staticTexts["guidePageIndicator"]
        XCTAssertTrue(indicator.waitForExistence(timeout: 5))
        func checkPage(_ number: Int) {
            expectation(for: NSPredicate(format: "label == %@", "\(number) of 5"), evaluatedWith: indicator)
            waitForExpectations(timeout: 5)
        }
        checkPage(1)
        XCTAssertFalse(app.buttons["guideBack"].isEnabled)
        XCTAssertTrue(app.staticTexts["May drop while moving. Auto-recovery reconnects; occasionally needs attention."].isHittable)
        capture("guide-0-connection-methods")
        app.swipeLeft()
        checkPage(2)
        XCTAssertTrue(app.staticTexts["Restore a full setup"].isHittable)
        capture("guide-1-restore")
        app.swipeRight()
        checkPage(1)
        app.buttons["guideNext"].tap()
        checkPage(2)
        app.buttons["guideNext"].tap()
        checkPage(3)
        XCTAssertTrue(app.staticTexts["Add an Amnezia profile"].isHittable)
        capture("guide-2-amnezia")
        app.buttons["guideNext"].tap()
        checkPage(4)
        XCTAssertTrue(app.staticTexts["Set up TURN and DNS"].isHittable)
        XCTAssertTrue(app.staticTexts["Optional — skip if included in your backup"].isHittable)
        capture("guide-3-turn-dns")
        app.buttons["guideNext"].tap()
        checkPage(5)
        XCTAssertTrue(app.staticTexts["Split tunneling"].isHittable)
        XCTAssertTrue(app.staticTexts["Tunnel selected addresses only"].isHittable)
        capture("guide-4-split")
        XCTAssertEqual(app.buttons["guideNext"].label, "Done")
        app.buttons["guideNext"].tap()
        XCTAssertTrue(app.buttons["automationSettings"].waitForExistence(timeout: 5))
        help.tap()
        checkPage(1)
        app.buttons["closeConnectionGuide"].tap()
        XCTAssertTrue(help.waitForExistence(timeout: 5))
    }

    func testConnectionGuideFitsIPadLandscape() throws {
        guard UIDevice.current.userInterfaceIdiom == .pad else {
            throw XCTSkip("Checks the guide's landscape layout on iPad.")
        }
        app.buttons["connectionGuide"].tap()
        let indicator = app.staticTexts["guidePageIndicator"]
        XCTAssertTrue(indicator.waitForExistence(timeout: 5))
        XCUIDevice.shared.orientation = .landscapeLeft
        defer { XCUIDevice.shared.orientation = .portrait }
        let lastTextOnEachPage = [
            "Amnezia for speed; TURN when VK is available; DNS for messages under strict restrictions.",
            "Your backup contains connection keys. Keep it private.",
            "Allow iOS to add a VPN configuration if asked. If your backup already contains this profile, you can connect straight away.",
            "For a fixed Wi-Fi DNS, enable Separate DNS for Wi-Fi (for example, 8.8.8.8).",
            "Each mode keeps its own list. Only one mode can be active. Off sends all traffic through the selected VPN."
        ]
        for (index, text) in lastTextOnEachPage.enumerated() {
            expectation(for: NSPredicate(format: "label == %@", "\(index + 1) of 5"), evaluatedWith: indicator)
            waitForExpectations(timeout: 5)
            let end = app.staticTexts[text]
            XCTAssertTrue(end.isHittable, "Page \(index + 1) must fit without vertical scrolling")
            XCTAssertLessThanOrEqual(end.frame.maxY, app.buttons["guideNext"].frame.minY)
            capture("guide-ipad-landscape-\(index)")
            app.buttons["guideNext"].tap()
        }
        XCTAssertTrue(app.buttons["connectionGuide"].waitForExistence(timeout: 5))
    }

    func testSubscriptionSingleKeyFormAndPasteValidation() {
        let open = app.buttons["openSubscription"]
        XCTAssertTrue(open.waitForExistence(timeout: 10)); XCTAssertTrue(open.isHittable)
        XCTAssertTrue(app.buttons["refreshSubscriptions"].isHittable)
        open.tap()
        let input = app.textFields["activationInput"]
        XCTAssertTrue(input.waitForExistence(timeout: 5)); XCTAssertEqual(app.textFields.count, 1)
        XCTAssertFalse(app.textFields["activationDeviceName"].exists)
        XCTAssertFalse(app.buttons["Scan QR"].exists)
        let add = app.buttons["activateAccess"]
        XCTAssertFalse(add.isEnabled)
        input.tap(); input.typeText("qwr")
        XCTAssertFalse(add.isEnabled)
        input.typeText("t")
        XCTAssertEqual(input.value as? String, "QWRT"); XCTAssertTrue(add.isEnabled)
        XCTAssertTrue(add.isHittable)
        capture("subscription-four-letter-form")
        input.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: 4))
        paste("tndtun://activate?code=QWRT", into: input)
        XCTAssertTrue(app.staticTexts["subscriptionError"].waitForExistence(timeout: 5))
        XCTAssertFalse(add.isEnabled, "A pasted link must not become the unrelated key TNDT")
        paste(" qWrT\n", into: input)
        XCTAssertEqual(input.value as? String, "QWRT"); XCTAssertTrue(add.isEnabled)
        XCTAssertFalse(app.staticTexts["subscriptionError"].exists)
    }

    func testSubscriptionAddSuccessAndSavedSubscriptionRefresh() {
        app.terminate(); app.launchEnvironment["TNDTUN_UI_SUBSCRIPTION"] = "success"; app.launch()
        addTURN("203.0.113.15")
        app.terminate()
        app.launchArguments = ["--ui-testing", "-UIPreferredContentSizeCategoryName", "UICTContentSizeCategoryAccessibilityXXXL"]
        app.launch()
        let homeRefresh = app.buttons["refreshSubscriptions"]
        let initialRefreshFrame = homeRefresh.frame
        let initialCardTop = app.otherElements["connectionStatusCard"].frame.minY
        app.buttons["openSubscription"].tap()
        let input = app.textFields["activationInput"]
        XCTAssertTrue(input.waitForExistence(timeout: 5)); input.tap(); input.typeText("qwrt")
        app.buttons["activateAccess"].tap()
        XCTAssertTrue(app.staticTexts["subscriptionAdded"].waitForExistence(timeout: 10))
        capture("subscription-added")
        app.buttons["subscriptionAddedDone"].tap()
        XCTAssertEqual(homeRefresh.frame, initialRefreshFrame)
        XCTAssertEqual(app.otherElements["connectionStatusCard"].frame.minY, initialCardTop)
        let savedUpdate = homeRefresh.value as? String
        XCTAssertFalse((savedUpdate ?? "").isEmpty)
        app.terminate()
        app.launchArguments = ["--ui-testing"]
        app.launch()
        XCTAssertEqual(homeRefresh.value as? String, savedUpdate)
        XCTAssertEqual(app.buttons.matching(NSPredicate(format: "identifier BEGINSWITH 'connect_'")).count, 2)
        app.buttons["openSubscription"].tap()
        let refresh = app.buttons["Refresh subscription"]
        XCTAssertTrue(refresh.waitForExistence(timeout: 5)); XCTAssertEqual(app.textFields.count, 0)
        XCTAssertTrue(app.staticTexts.matching(NSPredicate(format: "label CONTAINS %@", "QWRT")).firstMatch.exists)
        refresh.tap()
        let updated = expectation(for: NSPredicate(format: "enabled == true"), evaluatedWith: refresh)
        wait(for: [updated], timeout: 10)
        XCTAssertFalse(app.staticTexts["subscriptionError"].exists)
        XCTAssertTrue(app.buttons["addSubscription"].isHittable)
        XCTAssertFalse(app.staticTexts["Remove subscription from this device?"].exists)
        capture("subscription-saved-list")
        app.buttons["addSubscription"].tap()
        XCTAssertTrue(app.textFields["activationInput"].waitForExistence(timeout: 5))
        XCTAssertEqual(app.textFields.count, 1)
        app.buttons["closeSubscriptionAddition"].tap()
        XCTAssertTrue(app.buttons["Refresh subscription"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts.matching(NSPredicate(format: "label CONTAINS %@", "QWRT")).firstMatch.exists)
        app.buttons["Done"].tap()
        app.terminate()
        app.launchArguments = ["--ui-testing"]
        app.launch()
        app.buttons["openSubscription"].tap()
        XCTAssertTrue(app.staticTexts.matching(NSPredicate(format: "label CONTAINS %@", "QWRT")).firstMatch.waitForExistence(timeout: 5))
    }

    func testSubscriptionInvalidKeyShowsInlineErrorAndCanRetry() {
        app.buttons["openSubscription"].tap()
        let input = app.textFields["activationInput"]
        XCTAssertTrue(input.waitForExistence(timeout: 5)); input.tap(); input.typeText("qwrt")
        let add = app.buttons["activateAccess"]; add.tap()
        let message = app.staticTexts["subscriptionError"]
        XCTAssertTrue(message.waitForExistence(timeout: 10))
        XCTAssertTrue(message.label.contains("invalid or expired")); XCTAssertTrue(add.isEnabled)
        XCTAssertFalse(app.alerts["Action failed"].exists)
        capture("subscription-invalid-key")
    }

    private func paste(_ value: String, into input: XCUIElement) {
        UIPasteboard.general.string = value
        input.press(forDuration: 1.1)
        let menu = app.menuItems["Paste"]
        if menu.waitForExistence(timeout: 2) { menu.tap() }
        else {
            let paste = app.buttons["Paste"]
            XCTAssertTrue(paste.waitForExistence(timeout: 3)); paste.tap()
        }
    }

    func testStatusCardKeepsGeometryAcrossConnectionLifecycle() {
        addTURN("203.0.113.10")
        let profile = app.buttons.matching(NSPredicate(format: "identifier BEGINSWITH 'connect_'")).firstMatch
        app.launchEnvironment["TNDTUN_UI_PROFILE_ID"] = String(profile.identifier.dropFirst("connect_".count))
        for category in ["UICTContentSizeCategoryL", "UICTContentSizeCategoryXXXL", "UICTContentSizeCategoryAccessibilityXXXL"] {
            var reference: (card: CGRect, modes: CGRect, action: CGRect)?
            for state in ["disconnected", "connecting", "connected", "disconnecting", "disconnected"] {
                app.terminate()
                app.launchEnvironment["TNDTUN_UI_CONNECTION_STATE"] = state
                app.launchArguments = ["--ui-testing", "-UIPreferredContentSizeCategoryName", category]
                app.launch()
                let card = app.otherElements["connectionStatusCard"]
                XCTAssertTrue(card.waitForExistence(timeout: 10))
                let action = app.buttons[state == "disconnected" ? "connectSelected" : "disconnect"]
                XCTAssertTrue(action.exists)
                XCTAssertGreaterThanOrEqual(action.frame.height, 44)
                let modes = app.segmentedControls["modePicker"]
                XCTAssertTrue(modes.exists)
                XCTAssertGreaterThanOrEqual(card.frame.minY, 0)
                XCTAssertLessThanOrEqual(card.frame.maxY, app.frame.maxY)
                if let reference {
                    XCTAssertEqual(card.frame.height, reference.card.height, accuracy: 1, "Card changed height: \(state), \(category)")
                    XCTAssertEqual(modes.frame.minY, reference.modes.minY, accuracy: 1)
                    XCTAssertEqual(action.frame.minY, reference.action.minY, accuracy: 1)
                    XCTAssertEqual(action.frame.height, reference.action.height, accuracy: 1)
                } else { reference = (card.frame, modes.frame, action.frame) }
                capture("status-stable-\(category)-\(state)")
            }
        }
    }

    func testCompactConnectionStatesAndManualVerification() {
        addTURN("203.0.113.10")
        let profile = app.buttons.matching(NSPredicate(format: "identifier BEGINSWITH 'connect_'")).firstMatch
        app.launchEnvironment["TNDTUN_UI_PROFILE_ID"] = String(profile.identifier.dropFirst("connect_".count))
        for state in ["disconnected", "connecting", "captcha", "connected", "retry"] {
            app.terminate()
            app.launchEnvironment["TNDTUN_UI_CONNECTION_STATE"] = state
            app.launchArguments = ["--ui-testing"]
            if state == "retry" { app.launchArguments += ["-UIPreferredContentSizeCategoryName", "UICTContentSizeCategoryXXXL"] }
            app.launch()
            let card = app.otherElements["connectionStatusCard"]
            XCTAssertTrue(card.waitForExistence(timeout: 10))
            let status = app.staticTexts["connectionStatus"]
            XCTAssertTrue(status.isHittable)
            XCTAssertGreaterThanOrEqual(status.frame.minY - card.frame.minY, 8)
            XCTAssertLessThanOrEqual(status.frame.minY - card.frame.minY, 18)
            XCTAssertLessThanOrEqual(status.frame.maxX, app.buttons["pingConnection"].frame.minX)
            XCTAssertLessThan(app.buttons["refreshSubscriptions"].frame.maxY, card.frame.minY)
            XCTAssertGreaterThan(app.segmentedControls["modePicker"].frame.minY, card.frame.maxY)
            let statusBar = app.statusBars.firstMatch
            if statusBar.exists { XCTAssertGreaterThanOrEqual(app.buttons["automationSettings"].frame.minY, statusBar.frame.maxY) }
            XCTAssertEqual(app.buttons["completeVKVerification"].exists, state == "captcha",
                           "A pending challenge must keep a manual action even with automatic verification enabled")
            XCTAssertFalse(app.staticTexts["Access active"].exists)
            XCTAssertFalse(app.staticTexts["Подписка активна"].exists)
            if state == "disconnected" { XCTAssertEqual(status.label, "Disconnected") }
            if state == "connecting" { XCTAssertEqual(status.label, "Connecting…") }
            if state == "connected" { XCTAssertEqual(status.label, "Connected") }
            if state == "retry" { XCTAssertTrue(status.label.contains("Please retry.")); XCTAssertGreaterThan(status.frame.height, 30) }
            checkStatusActions(card)
            capture("compact-status-\(state)")

            if state == "captcha" {
                let manual = app.buttons["completeVKVerification"]
                XCTAssertTrue(manual.waitForExistence(timeout: 5)); XCTAssertTrue(manual.isHittable)
                XCTAssertEqual(status.label, "VK verification required")
                checkStatusActions(card)
                capture("compact-status-manual-verification")
            }
        }
    }

    private func checkStatusActions(_ card: XCUIElement) {
        let actions = ["disconnect", "retryConnection", "completeVKVerification"].map { app.buttons[$0] }.filter(\.exists)
        for button in actions {
            XCTAssertTrue(button.isHittable)
            XCTAssertGreaterThanOrEqual(button.frame.height, 44)
            XCTAssertLessThanOrEqual(button.frame.maxY, card.frame.maxY - 8)
            let text = button.staticTexts.firstMatch
            if text.exists { XCTAssertEqual(text.frame.midY, button.frame.midY, accuracy: 2) }
        }
        if let bottom = actions.map(\.frame.maxY).max() {
            XCTAssertEqual(card.frame.maxY - bottom, 10, accuracy: 2)
        }
    }

    func testAmneziaKeyPasteSaveModeIsolationAndBackup() {
        app.segmentedControls["modePicker"].buttons["Amnezia"].tap()
        app.buttons["addConfiguration"].tap()
        UIPasteboard.general.string = """
        [Interface]
        PrivateKey = \(Data(repeating: 17, count: 32).base64EncodedString())
        Address = 10.80.0.2/32
        Jc = 3
        Jmin = 30
        Jmax = 60
        S1 = 17
        S2 = 19
        H1 = 150
        H2 = 250
        H3 = 350
        H4 = 450
        [Peer]
        PublicKey = \(Data(repeating: 51, count: 32).base64EncodedString())
        Endpoint = 203.0.113.25:47891
        AllowedIPs = 0.0.0.0/0
        """
        app.buttons["pasteAmneziaKey"].tap()
        XCTAssertTrue(app.staticTexts["Key imported. Tap Save."].waitForExistence(timeout: 5))
        XCTAssertFalse(app.textFields["vlessID"].exists)
        app.buttons["saveConfiguration"].tap()
        XCTAssertTrue(app.staticTexts["203.0.113.25:47891"].waitForExistence(timeout: 5))
        capture("amnezia-imported")
        app.segmentedControls["modePicker"].buttons["TURN proxy"].tap()
        XCTAssertFalse(app.staticTexts["203.0.113.25:47891"].exists)
        app.segmentedControls["modePicker"].buttons["Amnezia"].tap()
        app.terminate(); app.launchArguments = ["--ui-testing"]; app.launch()
        XCTAssertTrue(app.staticTexts["203.0.113.25:47891"].waitForExistence(timeout: 10))
        app.buttons["automationSettings"].tap()
        app.segmentedControls["settingsTabs"].buttons["Transfer"].tap()
        app.buttons["exportApplicationBackup"].tap()
        XCTAssertTrue(app.textFields["DOCPicker.filenameTextField"].waitForExistence(timeout: 10))
        XCTAssertFalse(app.alerts["Action failed"].exists)
    }

    func testMultipleProfilesEditingModeIsolationPersistenceAndDeletion() {
        XCTAssertTrue(app.buttons["addConfiguration"].waitForExistence(timeout: 10))
        capture("01-turn-empty")
        addTURN("203.0.113.10")
        addTURN("203.0.113.20")
        XCTAssertTrue(app.staticTexts["203.0.113.10:56010"].exists)
        XCTAssertTrue(app.staticTexts["203.0.113.20:56010"].exists)
        capture("02-turn-profiles")
        app.buttons["Settings 203.0.113.10:56010"].tap()
        app.buttons["Edit"].tap()
        let field = app.textFields["turnServer"]
        XCTAssertTrue(field.waitForExistence(timeout: 5))
        field.tap()
        field.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: "203.0.113.10:56010".count) + "203.0.113.30:443")
        app.buttons["finishConfigurationInput"].tap()
        app.buttons["saveConfiguration"].tap()
        XCTAssertTrue(app.staticTexts["203.0.113.30:443"].waitForExistence(timeout: 5))
        app.segmentedControls["modePicker"].buttons["DNS tunnel"].tap()
        XCTAssertFalse(app.staticTexts["203.0.113.20:56010"].exists)
        app.buttons["addConfiguration"].tap()
        enter("dnsDomain", "tunnel.example.com")
        enter("dnsKey", String(repeating: "ab", count: 32))
        app.buttons["finishConfigurationInput"].tap()
        capture("03-dns-form")
        app.buttons["saveConfiguration"].tap()
        XCTAssertTrue(app.staticTexts["tunnel.example.com"].waitForExistence(timeout: 5))
        capture("04-dns-profile")
        app.terminate()
        app.launchArguments = ["--ui-testing"]
        app.launch()
        XCTAssertTrue(app.staticTexts["tunnel.example.com"].waitForExistence(timeout: 10))
        app.segmentedControls["modePicker"].buttons["TURN proxy"].tap()
        XCTAssertTrue(app.staticTexts["203.0.113.30:443"].exists)
        XCTAssertTrue(app.staticTexts["203.0.113.20:56010"].exists)
        app.buttons["Settings 203.0.113.30:443"].tap()
        app.buttons["Delete"].tap()
        app.buttons["Delete"].tap()
        let removed = app.staticTexts["203.0.113.30:443"]
        expectation(for: NSPredicate(format: "exists == false"), evaluatedWith: removed)
        waitForExpectations(timeout: 5)
        XCTAssertTrue(app.staticTexts["203.0.113.20:56010"].exists)
    }

    func testInvalidFormStaysOpenAndNeverCreatesProfile() {
        app.buttons["addConfiguration"].tap()
        enter("callLink", "https://example.com/call/join/test")
        enter("turnServer", "203.0.113.10")
        app.buttons["saveConfiguration"].tap()
        XCTAssertTrue(app.buttons["saveConfiguration"].exists)
        XCTAssertTrue(app.staticTexts["Enter a VK call link: https://vk.com/call/join/…"].exists)
        app.buttons["Cancel"].tap()
        XCTAssertFalse(app.staticTexts["203.0.113.10:56010"].exists)
    }

    func testClipboardJSONFillsBothModesAndSavesOnlyAfterConfirmation() {
        UIPasteboard.general.string = """
        {"mode":"turn","call_link":"https://vk.com/call/join/imported","server":"203.0.113.44","vless_id":"9f774dc1-395b-4397-890a-123456789abc"}
        """
        app.buttons["addConfiguration"].tap()
        XCTAssertTrue(app.textFields["vlessID"].exists)
        XCTAssertTrue(app.textFields["wrapKey"].exists)
        XCTAssertFalse(app.buttons["Advanced"].exists)
        app.buttons["pasteConfigurationJSON"].tap()
        XCTAssertTrue(app.staticTexts["Fields filled in. Tap Save."].waitForExistence(timeout: 5))
        XCTAssertEqual(app.textFields["callLink"].value as? String, "https://vk.com/call/join/imported")
        XCTAssertEqual(app.textFields["turnServer"].value as? String, "203.0.113.44:56010")
        XCTAssertEqual(app.textFields["vlessID"].value as? String, "9f774dc1-395b-4397-890a-123456789abc")
        capture("turn-imported-json-visible-fields")
        app.buttons["saveConfiguration"].tap()
        XCTAssertTrue(app.staticTexts["203.0.113.44:56010"].waitForExistence(timeout: 5))

        app.segmentedControls["modePicker"].buttons["DNS tunnel"].tap()
        UIPasteboard.general.string = """
        {"mode":"dns","domain":"imported.example.com","public_key":"\(String(repeating: "ab", count: 32))","tunnel_type":"socks5","resolver":"8.8.8.8"}
        """
        app.buttons["addConfiguration"].tap()
        app.buttons["pasteConfigurationJSON"].tap()
        XCTAssertTrue(app.staticTexts["Fields filled in. Tap Save."].waitForExistence(timeout: 5))
        XCTAssertEqual(app.textFields["dnsDomain"].value as? String, "imported.example.com")
        XCTAssertEqual(app.textFields["dnsKey"].value as? String, String(repeating: "ab", count: 32))
        capture("dns-imported-json")
        app.buttons["saveConfiguration"].tap()
        XCTAssertTrue(app.staticTexts["imported.example.com"].waitForExistence(timeout: 5))
        app.terminate(); app.launchArguments = ["--ui-testing"]; app.launch()
        XCTAssertTrue(app.staticTexts["imported.example.com"].waitForExistence(timeout: 10))
        app.buttons["Settings imported.example.com"].tap()
        app.buttons["Edit"].tap()
        app.swipeUp()
        XCTAssertEqual(app.textFields["dnsResolver"].value as? String, "8.8.8.8:53")
    }

    func testInvalidClipboardJSONKeepsExistingFieldsAndCancelDoesNotSave() {
        app.buttons["addConfiguration"].tap()
        enter("turnServer", "203.0.113.55")
        app.buttons["finishConfigurationInput"].tap()
        UIPasteboard.general.string = "{\"mode\":\"dns\"}"
        app.buttons["pasteConfigurationJSON"].tap()
        XCTAssertTrue(app.alerts["Could not paste JSON"].waitForExistence(timeout: 5))
        app.alerts.buttons["OK"].tap()
        XCTAssertEqual(app.textFields["turnServer"].value as? String, "203.0.113.55")
        app.buttons["Cancel"].tap()
        XCTAssertFalse(app.staticTexts["203.0.113.55:56010"].exists)
    }

    func testAutomationSaveCancelAndPersistence() {
        app.buttons["automationSettings"].tap()
        let recovery = app.switches["autoRecoveryToggle"]
        let autoStart = app.switches["autoConnectOnLaunchToggle"]
        XCTAssertEqual(autoStart.value as? String, "0")
        flip(autoStart)
        XCTAssertEqual(recovery.value as? String, "1")
        flip(recovery)
        app.buttons["Cancel"].tap()
        app.buttons["automationSettings"].tap()
        XCTAssertEqual(autoStart.value as? String, "0")
        flip(autoStart)
        flip(recovery)
        XCTAssertEqual(recovery.value as? String, "0")
        capture("automation-disabled-before-save")
        app.buttons["saveAutomation"].tap()
        app.terminate(); app.launchArguments = ["--ui-testing"]; app.launch()
        app.buttons["automationSettings"].tap()
        XCTAssertEqual(recovery.value as? String, "0")
        XCTAssertEqual(autoStart.value as? String, "1")
    }

    func testTURNChannelChoiceSaveCancelAndPersistence() {
        app.buttons["automationSettings"].tap()
        let channels = app.buttons["turnSessionCountPicker"]
        XCTAssertTrue(channels.waitForExistence(timeout: 5))
        if !channels.isHittable { app.swipeUp() }
        XCTAssertTrue((channels.value as? String ?? "").contains("10"))
        channels.tap(); app.buttons["1"].tap()
        app.buttons["Cancel"].tap()
        app.buttons["automationSettings"].tap()
        if !channels.isHittable { app.swipeUp() }
        XCTAssertTrue((channels.value as? String ?? "").contains("10"))
        channels.tap(); app.buttons["1"].tap()
        app.buttons["saveAutomation"].tap()
        app.terminate(); app.launchArguments = ["--ui-testing"]; app.launch()
        app.buttons["automationSettings"].tap()
        XCTAssertTrue(channels.waitForExistence(timeout: 5))
        if !channels.isHittable { app.swipeUp() }
        XCTAssertEqual(channels.value as? String, "1")
    }

    func testTURNBackgroundIntervalSaveCancelAndPersistence() {
        app.buttons["automationSettings"].tap()
        let interval = app.buttons["turnCheckIntervalPicker"]
        XCTAssertTrue(interval.waitForExistence(timeout: 5))
        XCTAssertEqual(interval.value as? String, "30 sec")
        interval.tap()
        app.buttons["2 min"].tap()
        XCTAssertEqual(interval.value as? String, "2 min")
        app.buttons["Cancel"].tap()
        app.buttons["automationSettings"].tap()
        XCTAssertEqual(interval.value as? String, "30 sec")
        interval.tap()
        app.buttons["2 min"].tap()
        capture("turn-background-check-interval")
        app.buttons["saveAutomation"].tap()
        app.terminate(); app.launchArguments = ["--ui-testing"]; app.launch()
        app.buttons["automationSettings"].tap()
        XCTAssertTrue(interval.waitForExistence(timeout: 5))
        XCTAssertEqual(interval.value as? String, "2 min")
        flip(app.switches["autoRecoveryToggle"])
        XCTAssertFalse(interval.isEnabled)
        flip(app.switches["autoRecoveryToggle"])
        XCTAssertTrue(interval.isEnabled)
        XCTAssertEqual(interval.value as? String, "2 min")
    }

    func testSplitTunnelSeparateListsJSONCancelAndPersistence() {
        openSplitSettings()
        app.buttons["splitMode_bypassSelected"].tap()
        enter("splitAddressField", "direct.test")
        app.buttons["addSplitAddress"].tap()
        app.buttons["splitMode_tunnelSelected"].tap()
        XCTAssertFalse(app.buttons["splitEntry_direct.test"].exists)
        enter("splitAddressField", "proxy.test")
        app.buttons["addSplitAddress"].tap()
        app.buttons["Cancel"].tap()
        openSplitSettings()
        XCTAssertEqual(app.buttons["splitMode_disabled"].value as? String, "Selected")
        app.buttons["splitMode_bypassSelected"].tap()
        enter("splitAddressField", "direct.test")
        app.buttons["addSplitAddress"].tap()
        app.buttons["splitMode_tunnelSelected"].tap()
        UIPasteboard.general.string = "{\"proxy.test\": [\"203.0.113.0/24\",\"203.0.113.0/24\"]}"
        let paste = app.buttons["pasteSplitJSON"]
        for _ in 0..<4 { if paste.isHittable { break }; app.swipeUp() }
        paste.tap()
        XCTAssertTrue(app.staticTexts["Addresses in list: 1."].waitForExistence(timeout: 5))
        app.swipeUp()
        XCTAssertTrue(app.buttons["splitEntry_proxy.test"].waitForExistence(timeout: 5))
        capture("split-imported-tunnel-list")
        app.buttons["saveAutomation"].tap()
        XCTAssertTrue(app.buttons["automationSettings"].waitForExistence(timeout: 5))
        app.terminate(); app.launchArguments = ["--ui-testing"]; app.launch()
        openSplitSettings()
        XCTAssertEqual(app.buttons["splitMode_tunnelSelected"].value as? String, "Selected")
        app.buttons["splitMode_bypassSelected"].tap()
        app.swipeUp()
        XCTAssertTrue(app.buttons["splitEntry_direct.test"].waitForExistence(timeout: 5))
        XCTAssertFalse(app.buttons["splitEntry_proxy.test"].exists)
        capture("split-bypass-list-after-restart")
    }

    func testApplicationBackupExportOpensSaveDialog() {
        addTURN("203.0.113.22")
        app.buttons["automationSettings"].tap()
        app.segmentedControls["settingsTabs"].buttons["Transfer"].tap()
        app.buttons["exportApplicationBackup"].tap()
        let filename = app.textFields["DOCPicker.filenameTextField"]
        XCTAssertTrue(filename.waitForExistence(timeout: 10))
        XCTAssertTrue((filename.value as? String)?.hasPrefix("TnDtun-backup-") == true)
        capture("backup-export-save-dialog")
        // Use a unique file name because Files retains previous test exports.
        filename.tap()
        filename.typeText("-" + UUID().uuidString)
        app.navigationBars["FullDocumentManagerViewControllerNavigationBar"].buttons["Save"].tap()
        XCTAssertTrue(app.staticTexts["Backup saved."].waitForExistence(timeout: 10))
        XCTAssertTrue(app.buttons["exportApplicationBackup"].waitForExistence(timeout: 5))
        expectation(for: NSPredicate(format: "isEnabled == true AND isHittable == true"),
                    evaluatedWith: app.buttons["exportApplicationBackup"])
        waitForExpectations(timeout: 10)
        app.buttons["exportApplicationBackup"].tap()
        XCTAssertTrue(filename.waitForExistence(timeout: 10))
    }

    func testApplicationBackupPreviewCancelReplaceAndPersistence() throws {
        addTURN("203.0.113.99")
        let profile: [String: Any] = ["id": "backup-turn", "mode": "turn",
            "callLink": "https://vk.ru/call/join/backup-ui", "server": "203.0.113.44:443",
            "vlessID": "810d5f7e-7a00-4a0c-95cd-7ac733a77816", "wrapKey": "", "dns": [:]]
        let dns: [String: Any] = ["id": "backup-dns", "mode": "dns", "callLink": "", "server": "",
            "vlessID": "", "wrapKey": "", "dns": ["domain": "backup.example.com", "publicKey": String(repeating: "ab", count: 32),
                "resolver": "203.0.113.53:53", "useWiFiResolver": true, "wifiResolver": "8.8.8.8:53", "sessionCount": 8]]
        let payload: [String: Any] = ["format": "TnDtun-backup", "schemaVersion": 1, "appVersion": "1.0", "appBuild": "7",
            "createdAt": "2026-10-04T12:00:00Z", "profiles": [profile, dns], "mode": "dns",
            "autoCaptcha": false, "autoRecovery": false, "savedDNSServers": ["203.0.113.53:53"],
            "selectedProfileID": "backup-dns", "splitTunneling": ["mode": "bypassSelected",
                "bypassEntries": [["address": "direct.example.com", "networks": [], "isNetworkGroup": false]],
                "tunnelEntries": [["address": "only.example.com", "networks": [], "isNetworkGroup": false]]]]
        UIPasteboard.general.string = String(decoding: try JSONSerialization.data(withJSONObject: payload), as: UTF8.self)
        app.buttons["automationSettings"].tap()
        app.segmentedControls["settingsTabs"].buttons["Transfer"].tap()
        XCTAssertTrue(app.buttons["exportApplicationBackup"].exists)
        capture("guide-01-import-file")
        app.buttons["pasteApplicationBackup"].tap()
        XCTAssertTrue(app.buttons["cancelApplicationBackup"].waitForExistence(timeout: 5))
        capture("backup-preview")
        capture("guide-02-confirm-import")
        app.buttons["cancelApplicationBackup"].tap()
        app.buttons["Cancel"].tap()
        XCTAssertTrue(app.staticTexts["203.0.113.99:56010"].waitForExistence(timeout: 5))
        app.buttons["automationSettings"].tap()
        app.segmentedControls["settingsTabs"].buttons["Transfer"].tap()
        app.buttons["pasteApplicationBackup"].tap()
        let confirm = app.buttons["confirmApplicationBackup"]
        XCTAssertTrue(confirm.waitForExistence(timeout: 5))
        if !confirm.isHittable { app.swipeUp() }
        confirm.tap()
        XCTAssertTrue(app.staticTexts["backup.example.com"].waitForExistence(timeout: 10))
        app.segmentedControls["modePicker"].buttons["TURN proxy"].tap()
        XCTAssertTrue(app.staticTexts["203.0.113.44:443"].exists)
        capture("guide-03-connect-profile")
        XCTAssertFalse(app.staticTexts["203.0.113.99:56010"].exists)
        app.terminate(); app.launchArguments = ["--ui-testing"]; app.launch()
        XCTAssertTrue(app.staticTexts["203.0.113.44:443"].waitForExistence(timeout: 10))
        app.buttons["automationSettings"].tap()
        XCTAssertEqual(app.switches["autoRecoveryToggle"].value as? String, "0")
        app.segmentedControls["settingsTabs"].buttons["Split tunneling"].tap()
        app.swipeUp()
        XCTAssertTrue(app.buttons["splitEntry_direct.example.com"].exists)
        app.swipeDown()
        app.buttons["splitMode_tunnelSelected"].tap()
        app.swipeUp()
        XCTAssertTrue(app.buttons["splitEntry_only.example.com"].exists)
        app.buttons["Cancel"].tap()
        app.segmentedControls["modePicker"].buttons["DNS tunnel"].tap()
        app.buttons["Settings backup.example.com"].tap(); app.buttons["Edit"].tap()
        XCTAssertEqual(app.textFields["dnsResolver"].value as? String, "203.0.113.53:53")
        app.swipeUp()
        XCTAssertEqual(app.switches["wifiDNSOverride"].value as? String, "1")
        XCTAssertEqual(app.textFields["wifiDNSResolver"].value as? String, "8.8.8.8:53")
    }

    private func openSplitSettings() {
        app.buttons["automationSettings"].tap()
        let tab = app.segmentedControls["settingsTabs"].buttons["Split tunneling"]
        XCTAssertTrue(tab.waitForExistence(timeout: 5)); tab.tap()
    }

    func testDNSResolverCanBeAddedAndReusedInAnotherProfile() {
        app.segmentedControls["modePicker"].buttons["DNS tunnel"].tap()
        app.buttons["addConfiguration"].tap()
        enter("dnsDomain", "tunnel.example.com")
        enter("dnsKey", String(repeating: "ab", count: 32))
        app.buttons["finishConfigurationInput"].tap()
        app.swipeUp()
        enter("newDNSResolver", "203.0.113.53")
        app.buttons["addDNSResolver"].tap()
        app.buttons["saveConfiguration"].tap()
        XCTAssertTrue(app.staticTexts["tunnel.example.com"].waitForExistence(timeout: 5))
        app.buttons["addConfiguration"].tap()
        app.swipeUp()
        let saved = app.buttons["selectDNS_203.0.113.53:53"]
        XCTAssertTrue(saved.waitForExistence(timeout: 5))
        saved.tap()
        XCTAssertEqual(app.textFields["dnsResolver"].value as? String, "203.0.113.53:53")
    }

    func testWiFiDNSOverrideShowsFieldAndPersistsIndependently() {
        app.segmentedControls["modePicker"].buttons["DNS tunnel"].tap()
        app.buttons["addConfiguration"].tap()
        enter("dnsDomain", "tunnel.example.com")
        enter("dnsKey", String(repeating: "ab", count: 32))
        app.buttons["finishConfigurationInput"].tap()
        let toggle = app.switches["wifiDNSOverride"]
        for _ in 0..<4 {
            if toggle.isHittable { break }
            app.swipeUp()
        }
        XCTAssertTrue(toggle.isHittable)
        XCTAssertEqual(toggle.value as? String, "0")
        XCTAssertFalse(app.textFields["wifiDNSResolver"].exists)
        flip(toggle)
        let field = app.textFields["wifiDNSResolver"]
        XCTAssertTrue(field.waitForExistence(timeout: 5))
        XCTAssertEqual(field.value as? String, "8.8.8.8")
        field.tap()
        field.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: 20) + "8.8.4.4:5353")
        app.buttons["finishConfigurationInput"].tap()
        capture("wifi-dns-override")
        app.buttons["saveConfiguration"].tap()
        XCTAssertTrue(app.staticTexts["tunnel.example.com"].waitForExistence(timeout: 5))
        app.terminate(); app.launchArguments = ["--ui-testing"]; app.launch()
        app.buttons["Settings tunnel.example.com"].tap()
        app.buttons["Edit"].tap()
        for _ in 0..<4 {
            if toggle.isHittable { break }
            app.swipeUp()
        }
        XCTAssertEqual(toggle.value as? String, "1")
        XCTAssertEqual(field.value as? String, "8.8.4.4:5353")
        flip(toggle)
        XCTAssertFalse(field.exists)
        flip(toggle)
        XCTAssertEqual(field.value as? String, "8.8.4.4:5353")
    }

    func testStatusConnectUsesExistingProfile() {
        addTURN("203.0.113.10", credential: true)
        let connect = app.buttons["connectSelected"]
        XCTAssertTrue(connect.isEnabled)
        connect.tap()
        XCTAssertTrue(app.alerts["Action failed"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["Test VPN connections on an iPhone or iPad. The simulator supports adding and editing profiles."].exists)
        app.buttons["OK"].tap()
        XCTAssertEqual(app.staticTexts["connectionStatus"].label, "Disconnected")
        XCTAssertEqual(app.buttons.matching(NSPredicate(format: "identifier BEGINSWITH 'connect_'")).count, 1)
    }

    func testSimulatorDoesNotPretendToBeConnected() {
        addTURN("203.0.113.10", credential: true)
        app.buttons["Connect 203.0.113.10:56010"].tap()
        XCTAssertTrue(app.alerts["Action failed"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["Test VPN connections on an iPhone or iPad. The simulator supports adding and editing profiles."].exists)
        app.buttons["OK"].tap()
        XCTAssertTrue(app.staticTexts["Disconnected"].exists)
    }

    private func addTURN(_ address: String, credential: Bool = false) {
        app.buttons["addConfiguration"].tap()
        enter("callLink", "https://vk.com/call/join/test-call")
        enter("turnServer", address)
        app.buttons["finishConfigurationInput"].tap()
        if credential {
            enter("vlessID", "9f774dc1-395b-4397-890a-123456789abc")
            app.buttons["finishConfigurationInput"].tap()
        }
        capture("turn-form")
        app.buttons["saveConfiguration"].tap()
        XCTAssertTrue(app.staticTexts[address + ":56010"].waitForExistence(timeout: 5))
    }

    private func enter(_ id: String, _ value: String) {
        let field = app.textFields[id]
        XCTAssertTrue(field.waitForExistence(timeout: 5))
        field.tap(); field.typeText(value)
    }

    private func flip(_ toggle: XCUIElement) {
        toggle.coordinate(withNormalizedOffset: CGVector(dx: 0.9, dy: 0.5)).tap()
    }

    private func capture(_ name: String) {
        let attachment = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        attachment.name = name; attachment.lifetime = .keepAlways
        add(attachment)
    }
}

/// Opt-in tests use the user's saved iPad profile, never UI fixtures or resets.
final class TnDtunPhysicalLifecycleUITests: XCTestCase {
    @MainActor func testAutoConnectOnActualAppRestartAndManualDisconnectWins() async throws {
        #if targetEnvironment(simulator) || targetEnvironment(macCatalyst)
        throw XCTSkip("Requires the authorized iPad and its saved Amnezia profile.")
        #else
        guard ProcessInfo.processInfo.environment["TNDTUN_LIVE_IPAD_UI"] == "1" else { throw XCTSkip("Opt in to physical lifecycle checks.") }
        continueAfterFailure = false
        let app = XCUIApplication()
        app.launchArguments = []
        app.launch()
        let status = app.staticTexts["connectionStatus"]
        func wait(_ value: String, seconds: TimeInterval = 60) {
            let found = XCTNSPredicateExpectation(predicate: NSPredicate(format: "label == %@", value), object: status)
            XCTAssertEqual(XCTWaiter.wait(for: [found], timeout: seconds), .completed)
        }
        if app.buttons["connectSelected"].waitForExistence(timeout: 5) { app.buttons["connectSelected"].tap() }
        wait("Connected")
        print("PHYSICAL_IDLE_BEGIN " + ISO8601DateFormatter().string(from: Date()))
        XCUIDevice.shared.press(.home)
        let idle = ProcessInfo.processInfo.environment["TNDTUN_SKIP_LONG_IDLE"] == "1" ? 3 : 245
        try await Task.sleep(for: .seconds(idle))
        app.activate()
        wait("Connected")
        app.buttons["pingConnection"].tap()
        try await Task.sleep(for: .seconds(3))
        let sessionConfig = URLSessionConfiguration.ephemeral
        sessionConfig.timeoutIntervalForRequest = 20; sessionConfig.timeoutIntervalForResource = 25
        let session = URLSession(configuration: sessionConfig)
        defer { session.invalidateAndCancel() }
        for raw in ["https://www.gstatic.com/generate_204", "https://www.youtube.com/", "https://speed.cloudflare.com/__down?bytes=1048576"] {
            let (data, response) = try await session.data(from: URL(string: raw)!)
            let code = try XCTUnwrap(response as? HTTPURLResponse).statusCode
            XCTAssertTrue((200..<400).contains(code))
            if raw.contains("bytes=") { XCTAssertGreaterThanOrEqual(data.count, 1_048_576) }
            print("PHYSICAL_AFTER_IDLE \(URL(string: raw)!.host!) status=\(code) bytes=\(data.count)")
        }
        print("PHYSICAL_IDLE_END " + ISO8601DateFormatter().string(from: Date()))
        app.buttons["automationSettings"].tap()
        let toggle = app.switches["autoConnectOnLaunchToggle"]
        XCTAssertTrue(toggle.waitForExistence(timeout: 5))
        let original = toggle.value as? String == "1"
        if !original { toggle.coordinate(withNormalizedOffset: CGVector(dx: 0.9, dy: 0.5)).tap() }
        XCTAssertEqual(toggle.value as? String, "1")
        app.buttons["saveAutomation"].tap()
        app.terminate(); app.launch()
        wait("Connected") // Existing provider must stay running.
        app.buttons["disconnect"].tap(); wait("Disconnected", seconds: 20)
        app.terminate(); app.launch()
        wait("Connected") // Permission exists: one fresh launch connects.
        app.buttons["disconnect"].tap(); wait("Disconnected", seconds: 20)
        XCUIDevice.shared.press(.home)
        app.activate()
        wait("Disconnected", seconds: 5) // Foreground is not a new launch.
        app.buttons["automationSettings"].tap()
        if !original { app.switches["autoConnectOnLaunchToggle"].coordinate(withNormalizedOffset: CGVector(dx: 0.9, dy: 0.5)).tap() }
        XCTAssertEqual(app.switches["autoConnectOnLaunchToggle"].value as? String, original ? "1" : "0")
        app.buttons["saveAutomation"].tap()
        app.buttons["connectSelected"].tap()
        wait("Connected") // Leave the tested profile working.
        #endif
    }
}
