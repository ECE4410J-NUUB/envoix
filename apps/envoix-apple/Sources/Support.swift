import SwiftUI
import AppKit
import CoreImage.CIFilterBuiltins

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

/// A labeled field for entering the shared pairing token, with a one-tap
/// generator (and copy) so users don't have to invent one.
struct TokenField: View {
    @Binding var token: String
    var disabled: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Shared token (same on both devices, \(minTokenLength)+ characters)")
                .font(.caption)
                .foregroundStyle(.secondary)
            HStack {
                TextField("e.g. envoix-lan-2026", text: $token)
                    .textFieldStyle(.roundedBorder)
                Button("Generate") { token = friendlyToken() }
                Button("Copy") { copyToPasteboard(token) }
                    .disabled(token.trimmed.isEmpty)
            }
            .disabled(disabled)
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
        VStack(spacing: 8) {
            switch viewModel.phase {
            case .idle:
                EmptyView()
            case .waiting:
                Label("Waiting for sender…", systemImage: "antenna.radiowaves.left.and.right")
                    .foregroundStyle(.secondary)
            case .transferring:
                ProgressView(value: viewModel.progressFraction)
                Text(viewModel.fileName)
                    .font(.caption)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .foregroundStyle(.secondary)
                HStack(spacing: 6) {
                    Text("\(byteString(viewModel.transferred)) / \(byteString(viewModel.total))")
                    if viewModel.bytesPerSec > 0 {
                        Text("·"); Text(rateString(viewModel.bytesPerSec))
                    }
                    if let eta = viewModel.etaSeconds {
                        Text("·"); Text(etaString(eta))
                    }
                }
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
            case .completed(let bytes):
                Label("Completed — \(byteString(bytes))", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
                if let url = viewModel.completedFileURL {
                    completedFileControls(url)
                }
            case .failed(let reason):
                Label(reason, systemImage: "xmark.octagon.fill")
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
            }

            if !viewModel.statusText.isEmpty {
                Text(viewModel.statusText)
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
        }
    }

    /// Reveal + copyable absolute path for a received file (handy for pasting
    /// into an AI or another tool).
    @ViewBuilder private func completedFileControls(_ url: URL) -> some View {
        HStack {
            Button("Reveal in Finder") { revealInFinder(url) }
            Button("Copy Path") { copyToPasteboard(url.path) }
        }
        Text(url.path)
            .font(.caption2.monospaced())
            .foregroundStyle(.secondary)
            .textSelection(.enabled)
            .lineLimit(1)
            .truncationMode(.middle)
    }
}
