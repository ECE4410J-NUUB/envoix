import SwiftUI
import AppKit
import CoreImage.CIFilterBuiltins

/// Minimum length of a shared pairing token, matching the core requirement.
let minTokenLength = 12

/// How two peers find and authenticate each other.
enum PairingMode: Hashable {
    case token   // same LAN, shared token, mDNS auto-discovery
    case invite  // QR / invite link carrying the receiver's address
}

extension String {
    var trimmed: String { trimmingCharacters(in: .whitespacesAndNewlines) }
}

/// A labeled field for entering the shared pairing token.
struct TokenField: View {
    @Binding var token: String
    var disabled: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Shared token (same on both devices, \(minTokenLength)+ characters)")
                .font(.caption)
                .foregroundStyle(.secondary)
            TextField("e.g. envoix-lan-2026", text: $token)
                .textFieldStyle(.roundedBorder)
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

/// Formats a byte count as a short human-readable string.
func byteString(_ bytes: UInt64) -> String {
    ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
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
                Text("\(viewModel.fileName) — \(byteString(viewModel.transferred)) / \(byteString(viewModel.total))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            case .completed(let bytes):
                Label("Completed — \(byteString(bytes))", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
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
}
