import SwiftUI
import AppKit

// MARK: - Card

private struct CardModifier: ViewModifier {
    var raised: Bool
    var padding: CGFloat

    func body(content: Content) -> some View {
        content
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(raised ? Theme.surfaceRaised : Theme.surface)
            .overlay(
                RoundedRectangle(cornerRadius: Theme.cardRadius)
                    .strokeBorder(Theme.line.opacity(0.75), lineWidth: 0.8)
            )
            .clipShape(RoundedRectangle(cornerRadius: Theme.cardRadius))
            .shadow(color: Color.black.opacity(raised ? 0.025 : 0), radius: raised ? 3 : 0, y: raised ? 1 : 0)
    }
}

extension View {
    /// Wraps content in a light rounded panel.
    func card(raised: Bool = false, padding: CGFloat = 16) -> some View {
        modifier(CardModifier(raised: raised, padding: padding))
    }
}

// MARK: - Pills

/// Rounded status chip (e.g. "Completed", "Waiting…", an error).
struct StatusPill: View {
    enum Kind { case success, warning, error, neutral }
    var text: String
    var systemImage: String?
    var kind: Kind = .success

    private var tint: Color {
        switch kind {
        case .success: return Theme.success
        case .warning: return Theme.warning
        case .error: return Theme.danger
        case .neutral: return Theme.muted
        }
    }

    var body: some View {
        HStack(spacing: 5) {
            if let systemImage { Image(systemName: systemImage) }
            Text(text)
        }
        .font(.body.weight(.semibold))
        .foregroundStyle(tint)
        .padding(.horizontal, 14)
        .padding(.vertical, 7)
        .background(tint.opacity(0.10))
        .clipShape(Capsule())
    }
}

/// Small accent chip marking the active pairing mode.
struct ModePill: View {
    var text: String

    var body: some View {
        Text(text)
            .font(.body.weight(.semibold))
            .foregroundStyle(Theme.accentStrong)
            .padding(.horizontal, 14)
            .padding(.vertical, 7)
            .background(Theme.accentSoft.opacity(0.75))
            .clipShape(Capsule())
    }
}

// MARK: - Pairing selector

/// Two-option selector for choosing the pairing transport without hiding the
/// behavioral difference between QR/link and token.
struct PairingModeSelector: View {
    @Binding var selection: PairingMode
    var disabled: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Pairing method")
                .font(.title3.weight(.semibold))
                .foregroundStyle(Theme.muted)

            HStack(spacing: 10) {
                option(
                    mode: .invite,
                    title: "Link / QR",
                    subtitle: "Best when one Mac starts receiving first.",
                    systemImage: "qrcode"
                )
                option(
                    mode: .token,
                    title: "Shared Token",
                    subtitle: "Same token on both devices, same network.",
                    systemImage: "key"
                )
            }
        }
        .card(padding: 14)
        .disabled(disabled)
    }

    private func option(
        mode: PairingMode,
        title: String,
        subtitle: String,
        systemImage: String
    ) -> some View {
        let selected = selection == mode

        return Button {
            selection = mode
        } label: {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: systemImage)
                    .font(.title3.weight(.semibold))
                    .frame(width: 28, height: 28)
                    .foregroundStyle(selected ? Theme.accentStrong : Theme.muted)

                VStack(alignment: .leading, spacing: 4) {
                    Text(title)
                        .font(.title3.weight(.semibold))
                        .foregroundStyle(selected ? Theme.accentStrong : Theme.text)
                    Text(subtitle)
                        .font(.callout)
                        .foregroundStyle(Theme.muted)
                        .lineLimit(2)
                }

                Spacer(minLength: 6)

                Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                    .font(.title3.weight(.semibold))
                    .foregroundStyle(selected ? Theme.accent : Theme.line)
            }
            .padding(12)
            .frame(maxWidth: .infinity, minHeight: 86, alignment: .leading)
            .contentShape(RoundedRectangle(cornerRadius: Theme.cardRadius))
        }
        .buttonStyle(.plain)
        .background(selected ? Theme.accentSoft : Theme.surface)
        .overlay(
            RoundedRectangle(cornerRadius: Theme.cardRadius)
                .strokeBorder(selected ? Theme.accent.opacity(0.55) : Theme.line.opacity(0.75), lineWidth: selected ? 1.2 : 0.8)
        )
        .clipShape(RoundedRectangle(cornerRadius: Theme.cardRadius))
    }
}

// MARK: - Progress

/// Slim, rounded progress track with an accent fill.
struct ProgressBar: View {
    var value: Double  // 0...1

    var body: some View {
        GeometryReader { geo in
            ZStack(alignment: .leading) {
                Capsule().fill(Theme.line.opacity(0.65))
                Capsule().fill(Theme.accent)
                    .frame(width: max(0, min(1, value)) * geo.size.width)
            }
        }
        .frame(height: 7)
    }
}

// MARK: - File drop

/// Dashed accent drop area on a soft accent background.
struct FileDropStyle: ViewModifier {
    var targeted: Bool

    func body(content: Content) -> some View {
        content
            .padding(16)
            .frame(maxWidth: .infinity)
            .background(Theme.surface)
            .overlay(
                RoundedRectangle(cornerRadius: Theme.cardRadius)
                    .strokeBorder(
                        targeted ? Theme.accent : Theme.accent.opacity(0.38),
                        style: StrokeStyle(lineWidth: targeted ? 2 : 1, dash: [6])
                    )
            )
            .clipShape(RoundedRectangle(cornerRadius: Theme.cardRadius))
    }
}

extension View {
    func fileDropStyle(targeted: Bool) -> some View { modifier(FileDropStyle(targeted: targeted)) }
}

// MARK: - Link row

/// A bordered row showing a value with trailing action buttons.
struct LinkRow<Trailing: View>: View {
    var text: String
    @ViewBuilder var trailing: Trailing

    var body: some View {
        HStack(spacing: 8) {
            Text(text)
                .font(.body.monospaced())
                .foregroundStyle(Theme.muted)
                .lineLimit(1)
                .truncationMode(.middle)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
            trailing
        }
        .padding(8)
        .background(Theme.surface)
        .overlay(
            RoundedRectangle(cornerRadius: Theme.cardRadius)
                .strokeBorder(Theme.line.opacity(0.75), lineWidth: 0.8)
        )
        .clipShape(RoundedRectangle(cornerRadius: Theme.cardRadius))
    }
}

// MARK: - QR card

/// White, bordered card framing a QR image (white in both themes, by design).
struct QRCard: View {
    var image: NSImage
    var size: CGFloat = 184

    var body: some View {
        Image(nsImage: image)
            .interpolation(.none)
            .resizable()
            .frame(width: size, height: size)
            .padding(14)
            .background(Color.white)
            .overlay(
                RoundedRectangle(cornerRadius: Theme.cardRadius)
                    .strokeBorder(Theme.line.opacity(0.75), lineWidth: 0.8)
            )
            .clipShape(RoundedRectangle(cornerRadius: Theme.cardRadius))
    }
}

// MARK: - Sidebar rail

/// Left-aligned navigation item with a selected (accent-soft) state.
struct RailButton: View {
    var title: String
    var systemImage: String
    var isSelected: Bool
    var badge: Int = 0
    var action: () -> Void
    @State private var isHovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                RoundedRectangle(cornerRadius: 2)
                    .fill(isSelected ? Theme.accent : Color.clear)
                    .frame(width: 4, height: 28)

                Image(systemName: systemImage)
                    .font(.title3.weight(.semibold))
                    .frame(width: 24)

                Text(title)
                    .font(.title3.weight(isSelected ? .semibold : .regular))

                Spacer(minLength: 8)

                if badge > 0 {
                    Text("\(badge)")
                        .font(.callout.weight(.bold))
                        .monospacedDigit()
                        .foregroundStyle(.white)
                        .padding(.horizontal, badge > 9 ? 7 : 8)
                        .frame(minHeight: 24)
                        .background(Theme.danger, in: Capsule())
                }
            }
            .padding(.horizontal, 10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .frame(minHeight: 54)
            .contentShape(RoundedRectangle(cornerRadius: 10))
        }
        .buttonStyle(.plain)
        .foregroundStyle(isSelected ? Theme.accentStrong : Theme.text)
        .background(
            isSelected ? Theme.accentSoft : (isHovering ? Theme.line.opacity(0.28) : Color.clear),
            in: RoundedRectangle(cornerRadius: 10)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .strokeBorder(isSelected ? Theme.accent.opacity(0.45) : Theme.line.opacity(0.72), lineWidth: 1)
        )
        .clipShape(RoundedRectangle(cornerRadius: 10))
        .contentShape(RoundedRectangle(cornerRadius: 10))
        .onHover { isHovering = $0 }
    }
}

// MARK: - Toast

/// Transient bottom message (e.g. "Invite copied"), shown via `ToastCenter`.
@MainActor
final class ToastCenter: ObservableObject {
    static let shared = ToastCenter()
    @Published var message: String?
    private var dismiss: Task<Void, Never>?

    func show(_ message: String) {
        self.message = message
        dismiss?.cancel()
        dismiss = Task {
            try? await Task.sleep(nanoseconds: 1_800_000_000)
            if !Task.isCancelled { self.message = nil }
        }
    }
}

private struct ToastOverlay: ViewModifier {
    @ObservedObject private var center = ToastCenter.shared

    func body(content: Content) -> some View {
        content.overlay(alignment: .bottom) {
            if let message = center.message {
                Text(message)
                    .font(.body.weight(.medium))
                    .foregroundStyle(.white)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 12)
                    .background(Color(light: 0x17202a, dark: 0x17202a))
                    .clipShape(RoundedRectangle(cornerRadius: Theme.cardRadius))
                    .shadow(color: Theme.shadowColor, radius: Theme.shadowRadius, y: Theme.shadowY)
                    .padding(.bottom, 22)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
            }
        }
        .animation(.spring(response: 0.3, dampingFraction: 0.8), value: center.message)
    }
}

extension View {
    /// Hosts transient toasts posted to `ToastCenter.shared`.
    func toastHost() -> some View { modifier(ToastOverlay()) }
}

/// Convenience: copy text and flash a toast.
@MainActor
func copyWithToast(_ text: String, _ message: String) {
    copyToPasteboard(text)
    ToastCenter.shared.show(message)
}
