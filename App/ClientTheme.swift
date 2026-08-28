import SwiftUI
import UIKit

enum ClientTheme {
    static let navy = Color(red: 30 / 255, green: 58 / 255, blue: 95 / 255)
    static let deepNavy = Color(red: 15 / 255, green: 23 / 255, blue: 42 / 255)
    static let accent = Color(uiColor: UIColor { traits in
        if traits.userInterfaceStyle == .dark {
            return UIColor(red: 74 / 255, green: 222 / 255, blue: 128 / 255, alpha: 1)
        }
        return UIColor(red: 22 / 255, green: 101 / 255, blue: 52 / 255, alpha: 1)
    })
    static let action = Color(red: 34 / 255, green: 197 / 255, blue: 94 / 255)
    static let mutedBlue = Color(red: 148 / 255, green: 163 / 255, blue: 184 / 255)
    static let danger = Color(red: 220 / 255, green: 38 / 255, blue: 38 / 255)
}
