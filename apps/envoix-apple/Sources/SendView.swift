import SwiftUI
import AppKit
import UniformTypeIdentifiers

struct SendView: View {
    @EnvironmentObject private var model: AppModel
    @ObservedObject var viewModel: TransferViewModel
    @State private var file: URL?
    @AppStorage("envoix.token") private var token: String = ""
    @AppStorage("envoix.concurrentTransfers") private var concurrentTransfers = true
    @AppStorage("envoix.language") private var language = "en"
    @AppStorage("envoix.serverURL") private var serverURL = ""
    @AppStorage("envoix.relayURL") private var relayURL = ""
    @AppStorage("envoix.speedLimit") private var speedLimit = 40
    @State private var invite: String = ""
    @State private var mode: PairingMode = .invite
    @State private var dropTargeted = false
    @State private var filePathInput = ""

    init(viewModel: TransferViewModel, initialMode: PairingMode = .invite) {
        self.viewModel = viewModel
        _mode = State(initialValue: initialMode)
    }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    fileSection
                    modeSelector

                    if mode == .invite {
                        inviteSection
                    } else {
                        TokenField(token: $token, disabled: viewModel.isBusy)
                            .card(padding: 14)
                    }

                    TransferStatusView(viewModel: viewModel)
                }
                .padding(.vertical, 12)
            }

            if concurrencyBlocked {
                Text("Finish receiving before starting a send.")
                    .font(.callout)
                    .foregroundStyle(Theme.muted)
                    .padding(.bottom, 8)
            }

            Button(action: primaryAction) {
                Label(primaryLabel, systemImage: viewModel.isBusy ? "xmark" : "paperplane")
                    .frame(maxWidth: .infinity, minHeight: 44)
                    .contentShape(Rectangle())
            }
            .keyboardShortcut(.defaultAction)
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .tint(viewModel.isBusy ? Theme.warning : Theme.accent)
            .disabled((!canSend || concurrencyBlocked) && !viewModel.isBusy)
            .padding(.top, 12)
        }
    }

    private var modeSelector: some View {
        PairingModeSelector(selection: $mode, disabled: viewModel.isBusy)
    }

    private var fileSection: some View {
        VStack(spacing: 12) {
            Button {
                if let url = chooseURL(directory: false) { selectFile(url) }
            } label: {
                VStack(spacing: 10) {
                    Image(systemName: file == nil ? "square.and.arrow.up" : "doc.fill")
                        .font(.system(size: 48, weight: .semibold))
                        .foregroundStyle(Theme.accentStrong)

                    Text(file?.lastPathComponent ?? "Drag here or click to choose")
                        .font(.title2.weight(.semibold))
                        .foregroundStyle(file == nil ? Theme.text : Theme.accentStrong)
                        .lineLimit(1)
                        .truncationMode(.middle)

                    Text(file == nil ? "Drop a file into this area, or click anywhere here to select one." : "Ready to share. Click this area to replace the file.")
                        .font(.body)
                        .foregroundStyle(Theme.muted)
                        .multilineTextAlignment(.center)
                        .lineLimit(2)
                }
                .frame(maxWidth: .infinity, minHeight: 150)
                .contentShape(RoundedRectangle(cornerRadius: Theme.cardRadius))
            }
            .buttonStyle(.plain)
            .disabled(viewModel.isBusy)

            filePathTools
        }
        .padding(18)
        .frame(maxWidth: .infinity)
        .background(dropTargeted ? Theme.accentSoft : Theme.surface)
        .overlay(
            RoundedRectangle(cornerRadius: Theme.cardRadius)
                .strokeBorder(
                    dropTargeted ? Theme.accent : Theme.accent.opacity(0.45),
                    style: StrokeStyle(lineWidth: dropTargeted ? 2 : 1.2, dash: [8])
                )
        )
        .clipShape(RoundedRectangle(cornerRadius: Theme.cardRadius))
        .onDrop(of: [.fileURL], isTargeted: $dropTargeted) { providers in
            guard !viewModel.isBusy, let provider = providers.first else { return false }
            _ = provider.loadObject(ofClass: URL.self) { url, _ in
                if let url { DispatchQueue.main.async { selectFile(url) } }
            }
            return true
        }
    }

    private var filePathTools: some View {
        HStack(spacing: 8) {
            Image(systemName: "link")
                .font(.callout.weight(.semibold))
                .foregroundStyle(Theme.muted)

            TextField("Paste an absolute file path here", text: $filePathInput)
                .textFieldStyle(.plain)
                .font(.callout.monospaced())
                .foregroundStyle(Theme.text)
                .onSubmit(applyPathInput)
                .disabled(viewModel.isBusy)

            Button(action: applyPathInput) {
                Label("Use Path", systemImage: "checkmark")
                    .labelStyle(.iconOnly)
                    .frame(width: 28, height: 28)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .foregroundStyle(filePathInput.trimmed.isEmpty ? Theme.muted : Theme.accentStrong)
            .disabled(viewModel.isBusy || filePathInput.trimmed.isEmpty)
            .help("Use pasted path")

            Button {
                if let file { copyWithToast(file.path, "File path copied") }
            } label: {
                Label("Copy Selected Path", systemImage: "doc.on.doc")
                    .labelStyle(.iconOnly)
                    .frame(width: 28, height: 28)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .foregroundStyle(file == nil ? Theme.muted : Theme.accentStrong)
            .disabled(file == nil)
            .help("Copy selected path")
        }
        .padding(.horizontal, 10)
        .frame(minHeight: 44)
        .background(Theme.surface)
        .overlay(
            RoundedRectangle(cornerRadius: Theme.cardRadius)
                .strokeBorder(Theme.line.opacity(0.75), lineWidth: 0.8)
        )
        .clipShape(RoundedRectangle(cornerRadius: Theme.cardRadius))
    }

    private var inviteSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            VStack(alignment: .leading, spacing: 3) {
                Text("Receiver invite link")
                    .font(.title3.weight(.semibold))
                    .foregroundStyle(Theme.text)
                Text("Paste the link generated on the receiving Mac.")
                    .font(.body)
                    .foregroundStyle(Theme.muted)
            }
            HStack(alignment: .top, spacing: 8) {
                TextField("envoix:…", text: $invite, axis: .vertical)
                    .textFieldStyle(.plain)
                    .font(.body.monospaced())
                    .foregroundStyle(Theme.text)
                    .lineLimit(1...3)
                    .disabled(viewModel.isBusy)
                Button {
                    invite = NSPasteboard.general.string(forType: .string)?.trimmed ?? invite
                    ToastCenter.shared.show("Invite pasted")
                } label: {
                    Label("Paste", systemImage: "doc.on.clipboard")
                        .frame(minHeight: 34)
                        .contentShape(Rectangle())
                }
                .disabled(viewModel.isBusy)
            }
            .padding(.horizontal, 10)
            .frame(minHeight: 44)
            .background(Theme.surface)
            .overlay(
                RoundedRectangle(cornerRadius: Theme.cardRadius)
                    .strokeBorder(Theme.line.opacity(0.75), lineWidth: 0.8)
            )
            .clipShape(RoundedRectangle(cornerRadius: Theme.cardRadius))
        }
        .card(padding: 14)
    }

    private var primaryLabel: String {
        if viewModel.isBusy { return "Cancel Transfer" }
        switch viewModel.phase {
        case .completed, .failed: return "Send Again"
        default: return "Send"
        }
    }

    private var canSend: Bool {
        guard file != nil else { return false }
        switch mode {
        case .invite:
            return !invite.trimmed.isEmpty
        case .token:
            return token.trimmed.count >= minTokenLength
        }
    }

    private var concurrencyBlocked: Bool {
        !concurrentTransfers && !viewModel.isBusy && model.receive.isBusy
    }

    private func selectFile(_ url: URL) {
        file = url
        filePathInput = url.path
    }

    private func applyPathInput() {
        let raw = filePathInput.trimmed
        guard !raw.isEmpty else { return }

        let path = (raw as NSString).expandingTildeInPath
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory), !isDirectory.boolValue else {
            ToastCenter.shared.show("File path not found")
            return
        }

        selectFile(URL(fileURLWithPath: path))
        ToastCenter.shared.show("File path selected")
    }

    private func primaryAction() {
        if viewModel.isBusy {
            viewModel.cancel()
            return
        }
        guard let file else { return }
        do {
            let settings = try RuntimeSettingsProvider.make(
                concurrentTransfers: concurrentTransfers,
                language: language,
                serverURL: serverURL,
                relayURL: relayURL,
                speedLimit: speedLimit
            )
            switch mode {
            case .invite:
                viewModel.startSendingWithInvite(filePath: file.path, invite: invite.trimmed, settings: settings)
            case .token:
                viewModel.startSendingWithToken(filePath: file.path, token: token.trimmed, settings: settings)
            }
        } catch {
            viewModel.handleFailed(error.localizedDescription)
        }
    }
}
