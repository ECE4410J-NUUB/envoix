import SwiftUI

struct ReceiveView: View {
    @EnvironmentObject private var model: AppModel
    @ObservedObject var viewModel: TransferViewModel
    // Remembered across launches. Empty means "use the Downloads default".
    @AppStorage("envoix.outputDir") private var outputDirPath: String = ""
    @AppStorage("envoix.token") private var token: String = ""
    @AppStorage("envoix.concurrentTransfers") private var concurrentTransfers = true
    @AppStorage("envoix.language") private var language = "en"
    @AppStorage("envoix.serverURL") private var serverURL = ""
    @AppStorage("envoix.relayURL") private var relayURL = ""
    @AppStorage("envoix.speedLimit") private var speedLimit = 40
    @State private var mode: PairingMode = .invite
    @State private var revealAddress = false

    init(viewModel: TransferViewModel, initialMode: PairingMode = .invite) {
        self.viewModel = viewModel
        _mode = State(initialValue: initialMode)
    }

    /// Defaults to ~/Downloads until the user explicitly picks another folder.
    private var outputDir: URL {
        if !outputDirPath.isEmpty { return URL(fileURLWithPath: outputDirPath) }
        return FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first
            ?? FileManager.default.homeDirectoryForCurrentUser
    }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    outputSection
                    modeSelector

                    if mode == .invite {
                        inviteSection
                    } else {
                        TokenField(token: $token, disabled: viewModel.isBusy)
                            .card(padding: 14)
                    }

                    if !viewModel.peerAddress.isEmpty {
                        addressReveal
                    }

                    TransferStatusView(viewModel: viewModel)
                }
                .padding(.vertical, 12)
            }

            if concurrencyBlocked {
                Text("Finish sending before starting a receive.")
                    .font(.callout)
                    .foregroundStyle(Theme.muted)
                    .padding(.bottom, 8)
            }

            Button(action: primaryAction) {
                Label(primaryLabel, systemImage: viewModel.isBusy ? "xmark" : "tray.and.arrow.down")
                    .frame(maxWidth: .infinity, minHeight: 44)
                    .contentShape(Rectangle())
            }
            .keyboardShortcut(.defaultAction)
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .tint(viewModel.isBusy ? Theme.warning : Theme.accent)
            .disabled((!canStart || concurrencyBlocked) && !viewModel.isBusy)
            .padding(.top, 12)
        }
    }

    private var modeSelector: some View {
        PairingModeSelector(selection: $mode, disabled: viewModel.isBusy)
    }

    private var outputSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Save as")
                .font(.title3.weight(.semibold))
                .foregroundStyle(Theme.muted)
            LinkRow(text: outputDir.path) {
                Button {
                    if let url = chooseURL(directory: true) { outputDirPath = url.path }
                } label: {
                    Label("Select", systemImage: "folder")
                        .frame(minHeight: 34)
                        .contentShape(Rectangle())
                }
                .disabled(viewModel.isBusy)
            }
        }
        .card(padding: 14)
    }

    private var primaryLabel: String {
        if viewModel.isBusy { return "Cancel Transfer" }
        switch viewModel.phase {
        case .completed, .failed: return "Receive Again"
        default: return "Start Receiving"
        }
    }

    /// The invite (QR + string) is the pairing artifact meant to be shared, so
    /// it is shown directly.
    @ViewBuilder private var inviteSection: some View {
        VStack(spacing: 16) {
            VStack(spacing: 4) {
                Text("Share this QR or invite link")
                    .font(.title2.weight(.semibold))
                    .foregroundStyle(Theme.text)
                Text("Start receiving to generate a fresh link for the sender.")
                    .font(.body)
                    .foregroundStyle(Theme.muted)
                    .multilineTextAlignment(.center)
            }

            if let image = QRCode.image(from: viewModel.invite), !viewModel.invite.isEmpty {
                QRCard(image: image, size: 208)
            } else {
                VStack(spacing: 10) {
                    Image(systemName: "qrcode")
                        .font(.system(size: 72, weight: .medium))
                        .foregroundStyle(Theme.muted)
                    Text("QR code")
                        .font(.title3.weight(.semibold))
                        .foregroundStyle(Theme.muted)
                }
                .frame(width: 236, height: 236)
                .background(Theme.surface)
                .overlay(
                    RoundedRectangle(cornerRadius: Theme.cardRadius)
                        .strokeBorder(Theme.line.opacity(0.75), lineWidth: 0.8)
                )
                .clipShape(RoundedRectangle(cornerRadius: Theme.cardRadius))
            }
            LinkRow(text: viewModel.invite.isEmpty ? "Invite link" : viewModel.invite) {
                Button {
                    copyWithToast(viewModel.invite, "Invite copied")
                } label: {
                    Label("Copy", systemImage: "doc.on.doc")
                        .frame(minHeight: 34)
                        .contentShape(Rectangle())
                }
                .disabled(viewModel.invite.isEmpty)
                Button {
                    startReceiveWithInvite()
                    ToastCenter.shared.show("Invite regenerated")
                } label: {
                    Label("Regenerate", systemImage: "arrow.clockwise")
                        .frame(minHeight: 34)
                        .contentShape(Rectangle())
                }
                .disabled(viewModel.isBusy)
            }
        }
        .card(raised: true, padding: 18)
    }

    /// The raw network address carries the real IP, so it stays hidden until the
    /// user explicitly reveals it.
    @ViewBuilder private var addressReveal: some View {
        VStack(alignment: .leading, spacing: 8) {
            Button {
                revealAddress.toggle()
            } label: {
                Label(revealAddress ? "Hide address" : "Show address", systemImage: revealAddress ? "eye.slash" : "eye")
                    .contentShape(Rectangle())
            }
            .controlSize(.small)

            if revealAddress {
                Text(viewModel.peerAddress)
                    .font(.body.monospaced())
                    .foregroundStyle(Theme.muted)
                    .textSelection(.enabled)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        }
        .card(raised: true, padding: 14)
    }

    private var canStart: Bool {
        mode == .invite || token.trimmed.count >= minTokenLength
    }

    private var concurrencyBlocked: Bool {
        !concurrentTransfers && !viewModel.isBusy && model.send.isBusy
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
        case .invite:
            startReceiveWithInvite()
        case .token:
            startReceiveWithToken()
        }
    }

    private func startReceiveWithToken() {
        do {
            let settings = try RuntimeSettingsProvider.make(
                concurrentTransfers: concurrentTransfers,
                language: language,
                serverURL: serverURL,
                relayURL: relayURL,
                speedLimit: speedLimit
            )
            viewModel.startReceivingWithToken(outputDir: outputDir.path, token: token.trimmed, settings: settings)
        } catch {
            viewModel.handleFailed(error.localizedDescription)
        }
    }

    private func startReceiveWithInvite() {
        do {
            let settings = try RuntimeSettingsProvider.make(
                concurrentTransfers: concurrentTransfers,
                language: language,
                serverURL: serverURL,
                relayURL: relayURL,
                speedLimit: speedLimit
            )
            viewModel.startReceivingWithInvite(outputDir: outputDir.path, settings: settings)
        } catch {
            viewModel.handleFailed(error.localizedDescription)
        }
    }
}
