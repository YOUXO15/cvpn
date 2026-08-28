import SwiftUI

@main
struct TunnelClientApp: App {
    @StateObject private var profiles = ProfileRepository()
    @StateObject private var vpn = VPNController()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(profiles)
                .environmentObject(vpn)
                .tint(ClientTheme.accent)
                .preferredColorScheme(forcedColorScheme)
        }
    }

    private var forcedColorScheme: ColorScheme? {
        #if DEBUG
        switch ProcessInfo.processInfo.environment["Client_UI_TEST_COLOR_SCHEME"] {
        case "dark": return .dark
        case "light": return .light
        default: return nil
        }
        #else
        return nil
        #endif
    }
}
