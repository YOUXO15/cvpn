import XCTest

final class VisualUITests: XCTestCase {
    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    @MainActor
    func testPortraitAndLandscapeLayouts() throws {
        let app = XCUIApplication()
        app.launchArguments += ["-AppleLanguages", "(ru)", "-AppleLocale", "ru_RU"]
        XCUIDevice.shared.orientation = .portrait
        app.launch()

        XCTAssertTrue(app.navigationBars["VPN Client"].waitForExistence(timeout: 8))
        attachScreenshot(named: "home-small-phone-portrait")

        XCUIDevice.shared.orientation = .landscapeLeft
        XCTAssertTrue(app.navigationBars["VPN Client"].waitForExistence(timeout: 3))
        attachScreenshot(named: "home-small-phone-landscape")
        XCUIDevice.shared.orientation = .portrait
    }

    @MainActor
    func testDarkModeWithAccessibilityText() throws {
        let app = XCUIApplication()
        app.launchArguments += [
            "-AppleLanguages", "(ru)",
            "-AppleLocale", "ru_RU",
            "-UIPreferredContentSizeCategoryName", "UICTContentSizeCategoryAccessibilityXXXL",
        ]
        app.launchEnvironment["Client_UI_TEST_COLOR_SCHEME"] = "dark"
        XCUIDevice.shared.orientation = .portrait
        app.launch()

        XCTAssertTrue(app.navigationBars["VPN Client"].waitForExistence(timeout: 8))
        attachScreenshot(named: "home-dark-accessibility-text")
    }

    @MainActor
    private func attachScreenshot(named name: String) {
        let attachment = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}
