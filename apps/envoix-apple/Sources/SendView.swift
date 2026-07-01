import SwiftUI
import AppKit
import UniformTypeIdentifiers

struct SendView: View {
    @Environment(\.appLanguage) private var uiLanguage
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
    @State private var roomCode = ""
    @State private var mode: PairingMode = .room
    @State private var dropTargeted = false
    @State private var filePathInput = ""

    init(viewModel: TransferViewModel, initialMode: PairingMode = .room) {
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
                    } else if mode == .room {
                        RoomCodeField(
                            code: $roomCode,
                            disabled: viewModel.isBusy,
                            title: AppText.value("Receiver code", "接收码", language: uiLanguage),
                            placeholder: AppText.value("Code shown on the receiving Mac", "接收端屏幕上的码", language: uiLanguage),
                            helper: AppText.value("Enter the code shown on the receiving Mac, then send this file.", "输入接收端屏幕上的码，然后发送这个文件。", language: uiLanguage)
                        )
                        .card(padding: 14)
                    } else {
                        TokenField(token: $token, disabled: viewModel.isBusy)
                            .card(padding: 14)
                    }

                    TransferStatusView(viewModel: viewModel)
                }
                .padding(.vertical, 12)
            }

            if concurrencyBlocked {
                Text(AppText.value("Finish receiving before starting a send.", "请先完成接收任务，再开始发送。", language: uiLanguage))
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
        PairingModeSelector(selection: $mode, role: .send, disabled: viewModel.isBusy)
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

                    Text(file?.lastPathComponent ?? AppText.value("Drag here or click to choose", "拖到这里或点击选择", language: uiLanguage))
                        .font(.title2.weight(.semibold))
                        .foregroundStyle(file == nil ? Theme.text : Theme.accentStrong)
                        .lineLimit(1)
                        .truncationMode(.middle)

                    Text(file == nil
                         ? AppText.value("Drop a file into this area, or click anywhere here to select one.", "把文件拖到这里，或点击此区域选择文件。", language: uiLanguage)
                         : AppText.value("Ready to share. Click this area to replace the file.", "已准备好分享。点击此区域可替换文件。", language: uiLanguage))
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

            TextField(AppText.value("Paste an absolute file path here", "在这里粘贴绝对文件路径", language: uiLanguage), text: $filePathInput)
                .textFieldStyle(.plain)
                .font(.callout.monospaced())
                .foregroundStyle(Theme.text)
                .onSubmit(applyPathInput)
                .disabled(viewModel.isBusy)

            Button(action: applyPathInput) {
                Label(AppText.value("Use Path", "使用路径", language: uiLanguage), systemImage: "checkmark")
                    .labelStyle(.iconOnly)
                    .frame(width: 28, height: 28)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .foregroundStyle(filePathInput.trimmed.isEmpty ? Theme.muted : Theme.accentStrong)
            .disabled(viewModel.isBusy || filePathInput.trimmed.isEmpty)
            .help(AppText.value("Use pasted path", "使用粘贴的路径", language: uiLanguage))

            Button {
                if let file { copyWithToast(file.path, AppText.value("File path copied", "文件路径已复制", language: uiLanguage)) }
            } label: {
                Label(AppText.value("Copy Selected Path", "复制已选路径", language: uiLanguage), systemImage: "doc.on.doc")
                    .labelStyle(.iconOnly)
                    .frame(width: 28, height: 28)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .foregroundStyle(file == nil ? Theme.muted : Theme.accentStrong)
            .disabled(file == nil)
            .help(AppText.value("Copy selected path", "复制已选择文件的路径", language: uiLanguage))
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
                Text(AppText.value("Receiver invite link", "接收端邀请链接", language: uiLanguage))
                    .font(.title3.weight(.semibold))
                    .foregroundStyle(Theme.text)
                Text(AppText.value("Paste the link or QR result from the receiving Mac.", "粘贴接收端生成的链接或二维码内容。", language: uiLanguage))
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
                    ToastCenter.shared.show(AppText.value("Invite pasted", "邀请已粘贴", language: uiLanguage))
                } label: {
                    Label(AppText.value("Paste", "粘贴", language: uiLanguage), systemImage: "doc.on.clipboard")
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
        if viewModel.isBusy { return AppText.value("Cancel Transfer", "取消传输", language: uiLanguage) }
        switch viewModel.phase {
        case .completed, .canceled, .failed: return AppText.value("Send Again", "再次发送", language: uiLanguage)
        default: return AppText.value("Send", "发送", language: uiLanguage)
        }
    }

    private var canSend: Bool {
        guard file != nil else { return false }
        switch mode {
        case .room:
            return !roomCode.trimmed.isEmpty
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
            ToastCenter.shared.show(AppText.value("File path not found", "未找到文件路径", language: uiLanguage))
            return
        }

        selectFile(URL(fileURLWithPath: path))
        ToastCenter.shared.show(AppText.value("File path selected", "已选择文件路径", language: uiLanguage))
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
            case .room:
                viewModel.startSendingWithRoom(filePath: file.path, code: roomCode.trimmed, settings: settings)
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
