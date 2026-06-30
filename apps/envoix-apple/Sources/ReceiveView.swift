import SwiftUI

struct ReceiveView: View {
    @StateObject private var viewModel = TransferViewModel()
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
                addressSection
            }

            TransferStatusView(viewModel: viewModel)

            Spacer()

            Button(action: primaryAction) {
                Text(viewModel.isBusy ? "Cancel" : "Start Receiving")
                    .frame(maxWidth: .infinity)
            }
            .keyboardShortcut(.defaultAction)
            .controlSize(.large)
            .disabled(!canStart && !viewModel.isBusy)
        }
        .padding()
    }

    /// The invite/QR is hidden by default; revealed only on explicit request.
    @ViewBuilder private var addressSection: some View {
        VStack(spacing: 8) {
            Button(revealAddress ? "Hide Address" : "Show Address") {
                revealAddress.toggle()
            }
            .controlSize(.small)

            if revealAddress {
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
            } else {
                Text("Address hidden — click Show to reveal")
                    .font(.caption)
                    .foregroundStyle(.secondary)
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
