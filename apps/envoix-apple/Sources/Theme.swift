import SwiftUI
import AppKit

// MARK: - Dynamic colors

private extension NSColor {
    /// Builds an opaque sRGB color from a `0xRRGGBB` literal.
    convenience init(rgb: UInt32) {
        self.init(
            srgbRed: CGFloat((rgb >> 16) & 0xff) / 255,
            green: CGFloat((rgb >> 8) & 0xff) / 255,
            blue: CGFloat(rgb & 0xff) / 255,
            alpha: 1
        )
    }
}

extension Color {
    /// A color that resolves to `light` or `dark` (each `0xRRGGBB`) based on the
    /// effective appearance, so the system theme and `.preferredColorScheme`
    /// (driven by the in-app toggle) both switch it.
    init(light: UInt32, dark: UInt32) {
        self.init(nsColor: NSColor(name: nil) { appearance in
            let isDark = appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
            return NSColor(rgb: isDark ? dark : light)
        })
    }
}

// MARK: - Design tokens (from the reference demo)

enum Theme {
    static let bg = Color(light: 0xffffff, dark: 0x1b2027)
    static let surface = Color(light: 0xffffff, dark: 0x1b2027)
    static let surfaceRaised = Color(light: 0xffffff, dark: 0x1b2027)
    static let text = Color(light: 0x17202a, dark: 0xedf2f7)
    static let muted = Color(light: 0x647181, dark: 0xaab5c2)
    static let line = Color(light: 0xe5ebf1, dark: 0x303946)
    static let accent = Color(light: 0x0f6bff, dark: 0x6bb6ff)
    static let accentStrong = Color(light: 0x084fbd, dark: 0x9ed0ff)
    static let accentSoft = Color(light: 0xf0f6ff, dark: 0x182b40)
    static let success = Color(light: 0x147a4b, dark: 0x61d69a)
    static let warning = Color(light: 0xa05a00, dark: 0xffc166)
    static let danger = Color(light: 0xb42318, dark: 0xff8a80)
    static let dangerSoft = Color(light: 0xfff4f2, dark: 0x3a2020)

    static let cardRadius: CGFloat = 8
    static let pillRadius: CGFloat = 999

    /// Subtle shadow reserved for transient overlays.
    static let shadowColor = Color.black.opacity(0.08)
    static let shadowRadius: CGFloat = 8
    static let shadowY: CGFloat = 3
}

// MARK: - Appearance preference

/// User's appearance choice, persisted and applied at the app root.
enum Appearance: String, CaseIterable {
    case system, light, dark

    var colorScheme: ColorScheme? {
        switch self {
        case .system: return nil
        case .light: return .light
        case .dark: return .dark
        }
    }

    var icon: String {
        switch self {
        case .system: return "circle.lefthalf.filled"
        case .light: return "sun.max"
        case .dark: return "moon"
        }
    }

    var next: Appearance {
        let all = Appearance.allCases
        return all[(all.firstIndex(of: self)! + 1) % all.count]
    }
}

/// Compact sidebar control that cycles System → Light → Dark.
struct ThemeToggle: View {
    @AppStorage("envoix.appearance") private var appearance: Appearance = .system

    var body: some View {
        Button {
            appearance = appearance.next
        } label: {
            Label(appearance.rawValue.capitalized, systemImage: appearance.icon)
                .font(.title3)
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(RoundedRectangle(cornerRadius: 8))
        }
        .buttonStyle(.plain)
        .padding(.horizontal, 12)
        .frame(minHeight: 38)
        .foregroundStyle(Theme.muted)
        .contentShape(RoundedRectangle(cornerRadius: 8))
        .help("Toggle appearance (System / Light / Dark)")
    }
}
