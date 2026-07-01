import SwiftUI
import AppKit
import CoreImage.CIFilterBuiltins
import EnvoixCore

/// Minimum length of a shared pairing token, matching the core requirement.
let minTokenLength = 12
let defaultRendezvousBroker = "e946a31a2207efcd68b9dbf409c4bf241aa02a0cbc0028af2e1ed11472064eff@67.230.187.238:8445"
let defaultRelayURL = "https://envoix.chkxwlyh.us:8444"

/// Generates a short, memorable, easy-to-type pairing token of the form
/// `word-word-NN` (always ≥ `minTokenLength` since each word is ≥4 letters).
func friendlyToken() -> String {
    let words = ["river", "stone", "cloud", "tiger", "maple", "otter", "amber",
                 "comet", "delta", "ember", "flint", "grove", "ivory", "larch",
                 "mango", "ocean", "pearl", "raven", "spark", "topaz", "coral",
                 "hazel", "basil", "willow", "pine", "reef", "surf", "teal"]
    let a = words.randomElement()!
    var b = words.randomElement()!
    while b == a { b = words.randomElement()! }
    return "\(a)-\(b)-\(Int.random(in: 10...99))"
}

/// How two peers find and authenticate each other.
enum PairingMode: Hashable {
    case room    // rendezvous room, short code, broker-assisted pairing
    case invite  // QR / invite link carrying the receiver's address
    case token   // same LAN, shared token, mDNS auto-discovery
}

extension String {
    var trimmed: String { trimmingCharacters(in: .whitespacesAndNewlines) }
}

enum RuntimeSettingsProvider {
    static func make(
        concurrentTransfers: Bool,
        language: String,
        serverURL: String,
        relayURL: String,
        speedLimit: Int
    ) throws -> EnvoixRuntimeSettings {
        guard speedLimit >= 0 else {
            throw RuntimeSettingsError("Speed limit cannot be negative.")
        }

        return EnvoixRuntimeSettings(
            concurrentTransfers: concurrentTransfers,
            language: language,
            serverUrl: serverURL.trimmed,
            relayUrl: relayURL.trimmed,
            speedLimitMbps: UInt64(speedLimit)
        )
    }
}

func newRoomCode() -> String {
    (try? generateRoomCode()) ?? friendlyToken()
}

struct RuntimeSettingsError: LocalizedError {
    let message: String

    init(_ message: String) {
        self.message = message
    }

    var errorDescription: String? { message }
}

enum AppText {
    static func value(_ english: String, _ simplifiedChinese: String, language: String) -> String {
        language == "zh-Hans" ? simplifiedChinese : english
    }
}

private struct AppLanguageKey: EnvironmentKey {
    static let defaultValue = "en"
}

extension EnvironmentValues {
    var appLanguage: String {
        get { self[AppLanguageKey.self] }
        set { self[AppLanguageKey.self] = newValue }
    }
}

/// A labeled field for entering the shared pairing token, with a one-tap
/// generator (and copy) so users don't have to invent one.
struct TokenField: View {
    @Environment(\.appLanguage) private var language
    @Binding var token: String
    var disabled: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(AppText.value("Shared token (same on both devices, \(minTokenLength)+ characters)", "共享口令（两台设备相同，至少 \(minTokenLength) 个字符）", language: language))
                .font(.title3.weight(.semibold))
                .foregroundStyle(Theme.muted)
            HStack(spacing: 8) {
                TextField("e.g. envoix-lan-2026", text: $token)
                    .textFieldStyle(.plain)
                    .font(.body.monospaced())
                    .foregroundStyle(Theme.text)
                Button {
                    token = friendlyToken()
                    ToastCenter.shared.show(AppText.value("Token generated", "口令已生成", language: language))
                } label: {
                    Label(AppText.value("Generate", "生成", language: language), systemImage: "wand.and.stars")
                        .frame(minHeight: 34)
                        .contentShape(Rectangle())
                }
                Button {
                    copyWithToast(token, AppText.value("Token copied", "口令已复制", language: language))
                } label: {
                    Label(AppText.value("Copy Token", "复制口令", language: language), systemImage: "doc.on.doc")
                        .frame(minHeight: 34)
                        .contentShape(Rectangle())
                }
                    .disabled(token.trimmed.isEmpty)
            }
            .disabled(disabled)
            .padding(.horizontal, 10)
            .frame(minHeight: 44)
            .background(Theme.surface)
            .overlay(
                RoundedRectangle(cornerRadius: Theme.cardRadius)
                    .strokeBorder(Theme.line.opacity(0.75), lineWidth: 0.8)
            )
            .clipShape(RoundedRectangle(cornerRadius: Theme.cardRadius))
        }
    }
}

struct RoomCodeField: View {
    @Environment(\.appLanguage) private var language
    @Binding var code: String
    var disabled: Bool
    var title = "Room code"
    var placeholder = "135790-amber-comet"
    var canGenerate: Bool = false
    var generateLabel = "Generate"
    var copyLabel = "Copy Code"
    var helper: String

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title)
                .font(.title3.weight(.semibold))
                .foregroundStyle(Theme.muted)
            HStack(spacing: 8) {
                TextField(placeholder, text: $code)
                    .textFieldStyle(.plain)
                    .font(.body.monospaced())
                    .foregroundStyle(Theme.text)
                    .disabled(disabled)
                if canGenerate {
                    Button {
                        code = newRoomCode()
                        ToastCenter.shared.show(AppText.value("Room code generated", "接收码已生成", language: language))
                    } label: {
                        Label(generateLabel, systemImage: "wand.and.stars")
                            .frame(minHeight: 34)
                            .contentShape(Rectangle())
                    }
                    .disabled(disabled)
                }
                Button {
                    copyWithToast(code, AppText.value("Room code copied", "接收码已复制", language: language))
                } label: {
                    Label(copyLabel, systemImage: "doc.on.doc")
                        .frame(minHeight: 34)
                        .contentShape(Rectangle())
                }
                .disabled(code.trimmed.isEmpty)
            }
            .padding(.horizontal, 10)
            .frame(minHeight: 44)
            .background(Theme.surface)
            .overlay(
                RoundedRectangle(cornerRadius: Theme.cardRadius)
                    .strokeBorder(Theme.line.opacity(0.75), lineWidth: 0.8)
            )
            .clipShape(RoundedRectangle(cornerRadius: Theme.cardRadius))

            Text(helper)
                .font(.body)
                .foregroundStyle(Theme.muted)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

/// Renders a string into a crisp QR code image.
enum QRCode {
    static func image(from string: String) -> NSImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(string.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage else { return nil }
        let scaled = output.transformed(by: CGAffineTransform(scaleX: 8, y: 8))
        let rep = NSCIImageRep(ciImage: scaled)
        let image = NSImage(size: rep.size)
        image.addRepresentation(rep)
        return image
    }
}

/// Presents an open panel for a single file or directory; returns the choice.
func chooseURL(directory: Bool) -> URL? {
    let panel = NSOpenPanel()
    panel.canChooseFiles = !directory
    panel.canChooseDirectories = directory
    panel.allowsMultipleSelection = false
    return panel.runModal() == .OK ? panel.url : nil
}

func copyToPasteboard(_ text: String) {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(text, forType: .string)
}

/// Resolves a file from the clipboard, handling both a file copied in Finder
/// (a file-URL on the pasteboard) and a plain-text path (expanding a leading
/// `~`). Returns the URL only if it points to an existing file.
func pastedFileURL() -> URL? {
    let pb = NSPasteboard.general
    let exists = { FileManager.default.fileExists(atPath: $0) }

    if let urls = pb.readObjects(forClasses: [NSURL.self],
                                 options: [.urlReadingFileURLsOnly: true]) as? [URL],
       let url = urls.first, exists(url.path) {
        return url
    }
    if let raw = pb.string(forType: .string)?.trimmed, !raw.isEmpty {
        let expanded = (raw as NSString).expandingTildeInPath
        if exists(expanded) { return URL(fileURLWithPath: expanded) }
    }
    return nil
}

/// Selects the file in Finder (opening its enclosing folder).
func revealInFinder(_ url: URL) {
    NSWorkspace.shared.activateFileViewerSelecting([url])
}

/// Formats a byte count as a short human-readable string (auto KB/MB/GB).
func byteString(_ bytes: UInt64) -> String {
    ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
}

/// Formats a transfer rate, picking the most fitting unit (e.g. "12.3 MB/s").
func rateString(_ bytesPerSec: Double) -> String {
    byteString(UInt64(max(0, bytesPerSec))) + "/s"
}

/// Formats a remaining-time estimate as "ETA 1:20" / "ETA 1:02:03".
func etaString(_ seconds: Double) -> String {
    let s = Int(seconds.rounded())
    let (h, m, sec) = (s / 3600, (s % 3600) / 60, s % 60)
    if h > 0 { return String(format: "ETA %d:%02d:%02d", h, m, sec) }
    return String(format: "ETA %d:%02d", m, sec)
}

/// Shared status / progress section used by both the send and receive views.
struct TransferStatusView: View {
    @Environment(\.appLanguage) private var language
    @ObservedObject var viewModel: TransferViewModel

    var body: some View {
        if showsStatus {
            statusCard
        }
    }

    private var showsStatus: Bool {
        switch viewModel.phase {
        case .idle: return !viewModel.statusText.isEmpty
        default: return true
        }
    }

    private var statusCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: iconName)
                    .font(.title3.weight(.semibold))
                    .foregroundStyle(tint)
                    .frame(width: 30, height: 30)
                    .background(tint.opacity(0.10), in: Circle())

                VStack(alignment: .leading, spacing: 4) {
                    Text(titleText)
                        .font(.title3.weight(.semibold))
                        .foregroundStyle(Theme.text)
                        .lineLimit(2)

                    if let detailText {
                        Text(detailText)
                            .font(.body)
                            .foregroundStyle(Theme.muted)
                            .lineLimit(3)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }

                Spacer(minLength: 8)
            }

            switch viewModel.phase {
            case .idle, .waiting, .canceled, .failed:
                EmptyView()
            case .transferring:
                ProgressBar(value: viewModel.progressFraction)
                HStack(spacing: 6) {
                    Text("\(byteString(viewModel.transferred)) / \(byteString(viewModel.total))")
                    if viewModel.bytesPerSec > 0 {
                        Text("·"); Text(rateString(viewModel.bytesPerSec))
                    }
                    if let eta = viewModel.etaSeconds {
                        Text("·"); Text(etaString(eta))
                    }
                }
                .font(.body.monospacedDigit())
                .foregroundStyle(Theme.muted)
            case .completed(let bytes):
                Text(byteString(bytes))
                    .font(.body.monospacedDigit())
                    .foregroundStyle(Theme.muted)
                if let url = viewModel.completedFileURL {
                    completedFileControls(url)
                }
            }

            if let stepText {
                Text(stepText)
                    .font(.callout.monospaced())
                    .foregroundStyle(Theme.muted)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(backgroundTint)
        .overlay(
            RoundedRectangle(cornerRadius: Theme.cardRadius)
                .strokeBorder(tint.opacity(borderOpacity), lineWidth: 0.9)
        )
        .clipShape(RoundedRectangle(cornerRadius: Theme.cardRadius))
    }

    private var titleText: String {
        switch viewModel.phase {
        case .idle:
            return AppText.value("Status", "状态", language: language)
        case .waiting:
            return AppText.value("Waiting for the other device", "正在等待另一台设备", language: language)
        case .transferring:
            return viewModel.fileName.isEmpty ? AppText.value("Transferring", "正在传输", language: language) : viewModel.fileName
        case .completed:
            return AppText.value("Transfer completed", "传输完成", language: language)
        case .canceled:
            return AppText.value("Transfer canceled", "传输已取消", language: language)
        case .failed(let reason):
            return friendlyFailure(reason).title
        }
    }

    private var detailText: String? {
        switch viewModel.phase {
        case .idle:
            return viewModel.statusText.isEmpty ? nil : viewModel.statusText
        case .waiting:
            return viewModel.statusText.isEmpty
                ? AppText.value("Keep this window open until the peer connects.", "请保持此窗口打开，直到对方连接。", language: language)
                : viewModel.statusText
        case .transferring:
            return AppText.value("Keep both devices awake until the transfer finishes.", "请保持两台设备唤醒，直到传输完成。", language: language)
        case .completed:
            return viewModel.statusText.isEmpty ? AppText.value("The file is ready.", "文件已准备好。", language: language) : viewModel.statusText
        case .canceled:
            return AppText.value("Ready to start another transfer.", "可以开始新的传输。", language: language)
        case .failed(let reason):
            return friendlyFailure(reason).detail
        }
    }

    private var stepText: String? {
        let text = viewModel.statusText.trimmed
        guard !text.isEmpty else { return nil }
        if case .failed = viewModel.phase {
            return AppText.value("Last step: \(text)", "上一步：\(text)", language: language)
        }
        return nil
    }

    private var iconName: String {
        switch viewModel.phase {
        case .idle: return "info.circle"
        case .waiting: return "antenna.radiowaves.left.and.right"
        case .transferring: return "arrow.up.arrow.down.circle"
        case .completed: return "checkmark.circle.fill"
        case .canceled: return "xmark.circle"
        case .failed: return "exclamationmark.triangle.fill"
        }
    }

    private var tint: Color {
        switch viewModel.phase {
        case .idle: return Theme.muted
        case .waiting, .transferring: return Theme.warning
        case .completed: return Theme.success
        case .canceled: return Theme.muted
        case .failed: return Theme.danger
        }
    }

    private var backgroundTint: Color {
        switch viewModel.phase {
        case .failed: return Theme.dangerSoft.opacity(0.55)
        case .waiting, .transferring: return Theme.warning.opacity(0.06)
        case .completed: return Theme.success.opacity(0.06)
        case .idle, .canceled: return Theme.surface
        }
    }

    private var borderOpacity: Double {
        switch viewModel.phase {
        case .idle: return 0.25
        default: return 0.35
        }
    }

    private func friendlyFailure(_ reason: String) -> (title: String, detail: String) {
        let cleanReason = reason.trimmed
        let lower = cleanReason.lowercased()
        if lower.contains("mdns") && lower.contains("peers discovered") {
            return (
                AppText.value("No device found on the local network", "未在局域网发现设备", language: language),
                AppText.value("Make sure the other Mac is receiving with the same token and both devices are on the same network.", "请确认另一台 Mac 正在使用相同口令接收，并且两台设备在同一网络中。", language: language)
            )
        }
        if cleanReason.isEmpty {
            return (
                AppText.value("Transfer failed", "传输失败", language: language),
                AppText.value("Try again, or switch pairing method if discovery keeps failing.", "请重试；如果一直无法发现设备，请切换配对方式。", language: language)
            )
        }
        return (AppText.value("Transfer failed", "传输失败", language: language), cleanReason)
    }

    /// Reveal + copyable absolute path for a received file (handy for pasting
    /// into an AI or another tool).
    @ViewBuilder private func completedFileControls(_ url: URL) -> some View {
        HStack {
            Button(AppText.value("Reveal in Finder", "在 Finder 中显示", language: language)) { revealInFinder(url) }
            Button(AppText.value("Copy Path", "复制路径", language: language)) {
                copyWithToast(url.path, AppText.value("Path copied", "路径已复制", language: language))
            }
        }
        Text(url.path)
            .font(.body.monospaced())
            .foregroundStyle(Theme.muted)
            .textSelection(.enabled)
            .lineLimit(1)
            .truncationMode(.middle)
    }
}
