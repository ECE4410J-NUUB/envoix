import SwiftUI
import AppKit
import CoreImage.CIFilterBuiltins
import EnvoixCore

/// Minimum length of a shared pairing token, matching the core requirement.
let minTokenLength = 12

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
    case token   // same LAN, shared token, mDNS auto-discovery
    case invite  // QR / invite link carrying the receiver's address
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
            throw RuntimeSettingsError("Speed limit must be between 0 and 1000 MB/s.")
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

/// A labeled field for entering the shared pairing token, with a one-tap
/// generator (and copy) so users don't have to invent one.
struct TokenField: View {
    @Binding var token: String
    var disabled: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Shared token (same on both devices, \(minTokenLength)+ characters)")
                .font(.title3.weight(.semibold))
                .foregroundStyle(Theme.muted)
            HStack(spacing: 8) {
                TextField("e.g. envoix-lan-2026", text: $token)
                    .textFieldStyle(.plain)
                    .font(.body.monospaced())
                    .foregroundStyle(Theme.text)
                Button {
                    token = friendlyToken()
                    ToastCenter.shared.show("Token generated")
                } label: {
                    Label("Generate", systemImage: "wand.and.stars")
                        .frame(minHeight: 34)
                        .contentShape(Rectangle())
                }
                Button {
                    copyWithToast(token, "Token copied")
                } label: {
                    Label("Copy", systemImage: "doc.on.doc")
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
            case .idle, .waiting, .failed:
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
            return "Status"
        case .waiting:
            return "Waiting for the other device"
        case .transferring:
            return viewModel.fileName.isEmpty ? "Transferring" : viewModel.fileName
        case .completed:
            return "Transfer completed"
        case .failed(let reason):
            return friendlyFailure(reason).title
        }
    }

    private var detailText: String? {
        switch viewModel.phase {
        case .idle:
            return viewModel.statusText.isEmpty ? nil : viewModel.statusText
        case .waiting:
            return viewModel.statusText.isEmpty ? "Keep this window open until the peer connects." : viewModel.statusText
        case .transferring:
            return "Keep both devices awake until the transfer finishes."
        case .completed:
            return viewModel.statusText.isEmpty ? "The file is ready." : viewModel.statusText
        case .failed(let reason):
            return friendlyFailure(reason).detail
        }
    }

    private var stepText: String? {
        let text = viewModel.statusText.trimmed
        guard !text.isEmpty else { return nil }
        if case .failed = viewModel.phase {
            return "Last step: \(text)"
        }
        return nil
    }

    private var iconName: String {
        switch viewModel.phase {
        case .idle: return "info.circle"
        case .waiting: return "antenna.radiowaves.left.and.right"
        case .transferring: return "arrow.up.arrow.down.circle"
        case .completed: return "checkmark.circle.fill"
        case .failed: return "exclamationmark.triangle.fill"
        }
    }

    private var tint: Color {
        switch viewModel.phase {
        case .idle: return Theme.muted
        case .waiting, .transferring: return Theme.warning
        case .completed: return Theme.success
        case .failed: return Theme.danger
        }
    }

    private var backgroundTint: Color {
        switch viewModel.phase {
        case .failed: return Theme.dangerSoft.opacity(0.55)
        case .waiting, .transferring: return Theme.warning.opacity(0.06)
        case .completed: return Theme.success.opacity(0.06)
        case .idle: return Theme.surface
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
                "No device found on the local network",
                "Make sure the other Mac is receiving with the same token and both devices are on the same network."
            )
        }
        if cleanReason.isEmpty {
            return ("Transfer failed", "Try again, or switch pairing method if discovery keeps failing.")
        }
        return ("Transfer failed", cleanReason)
    }

    /// Reveal + copyable absolute path for a received file (handy for pasting
    /// into an AI or another tool).
    @ViewBuilder private func completedFileControls(_ url: URL) -> some View {
        HStack {
            Button("Reveal in Finder") { revealInFinder(url) }
            Button("Copy Path") { copyWithToast(url.path, "Path copied") }
        }
        Text(url.path)
            .font(.body.monospaced())
            .foregroundStyle(Theme.muted)
            .textSelection(.enabled)
            .lineLimit(1)
            .truncationMode(.middle)
    }
}
