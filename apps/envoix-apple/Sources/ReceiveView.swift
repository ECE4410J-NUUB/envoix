import SwiftUI

struct ReceiveView: View {
    @ObservedObject var viewModel: TransferViewModel
    // Remembered across launches. Empty means "use the Downloads default".
    @AppStorage("envoix.outputDir") private var outputDirPath: String = ""
    @AppStorage("envoix.token") private var token: String = ""
    @State private var mode: PairingMode = .token
    @State private var revealAddress = false

    /// Defaults to ~/Downloads until the user explicitly picks another folder.
    private var outputDir: URL {
        if !outputDirPath.isEmpty { return URL(fileURLWithPath: outputDirPath) }
        return FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first
            ?? FileManager.default.homeDirectoryForCurrentUser
    }

    var body: some View {
        VStack(spacing: 16) {
            Text("Receive a file").font(.title2.bold())

            Picker("", selection: $mode) {
                Text("Same network").tag(PairingMode.token)
                Text("Invite link").tag(PairingMode.invite)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .disabled(viewModel.isBusy)

            HStack {
                Text(outputDir.path)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer()
                Button("Select Another Folder") {
                    if let url = chooseURL(directory: true) { outputDirPath = url.path }
                }
                .disabled(viewModel.isBusy)
            }

            if mode == .token {
                TokenField(token: $token, disabled: viewModel.isBusy)
            } else if !viewModel.invite.isEmpty {
                inviteSection
            }

            if !viewModel.peerAddress.isEmpty {
                addressReveal
            }

            TransferStatusView(viewModel: viewModel)

            Spacer()

            Button(action: primaryAction) {
                Text(primaryLabel)
                    .frame(maxWidth: .infinity)
            }
            .keyboardShortcut(.defaultAction)
            .controlSize(.large)
            .disabled(!canStart && !viewModel.isBusy)
        }
        .padding()
    }

    private var primaryLabel: String {
        if viewModel.isBusy { return "Cancel" }
        switch viewModel.phase {
        case .completed, .failed: return "Receive Again"
        default: return "Start Receiving"
        }
    }

    /// The invite (QR + string) is the pairing artifact meant to be shared, so
    /// it is shown directly.
    @ViewBuilder private var inviteSection: some View {
        VStack(spacing: 8) {
            if let image = QRCode.image(from: viewModel.invite) {
                Image(nsImage: image)
                    .interpolation(.none)
                    .resizable()
                    .frame(width: 180, height: 180)
            }
            HStack {
                Text(viewModel.invite)
                    .font(.caption.monospaced())
                    .lineLimit(1)
                    .truncationMode(.middle)
                Button("Copy") { copyToPasteboard(viewModel.invite) }
                Button("Regenerate") { startReceive() }
            }
        }
    }

    /// The raw network address carries the real IP, so it stays hidden until the
    /// user explicitly reveals it.
    @ViewBuilder private var addressReveal: some View {
        VStack(spacing: 4) {
            Button(revealAddress ? "Hide Address" : "Show Address") {
                revealAddress.toggle()
            }
            .controlSize(.small)

            if revealAddress {
                Text(viewModel.peerAddress)
                    .font(.caption2.monospaced())
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        }
    }

    private var canStart: Bool {
        mode == .invite || token.trimmed.count >= minTokenLength
    }

    private func primaryAction() {
        if viewModel.isBusy {
            viewModel.cancel()
        } else {
            startReceive()
        }
    }

    /// Starts (or restarts, for "Regenerate") the receive session.
    private func startReceive() {
        switch mode {
        case .token:
            viewModel.startReceivingWithToken(outputDir: outputDir.path, token: token.trimmed)
        case .invite:
            viewModel.startReceivingWithInvite(outputDir: outputDir.path)
        }
    }
}
