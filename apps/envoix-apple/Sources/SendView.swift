import SwiftUI
import UniformTypeIdentifiers

struct SendView: View {
    @ObservedObject var viewModel: TransferViewModel
    @State private var file: URL?
    @AppStorage("envoix.token") private var token: String = ""
    @State private var invite: String = ""
    @State private var mode: PairingMode = .token
    @State private var dropTargeted = false

    var body: some View {
        VStack(spacing: 16) {
            Text("Send a file").font(.title2.bold())

            Picker("", selection: $mode) {
                Text("Same network").tag(PairingMode.token)
                Text("Invite link").tag(PairingMode.invite)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .disabled(viewModel.isBusy)

            VStack(spacing: 8) {
                HStack {
                    Image(systemName: file == nil ? "doc" : "doc.fill")
                        .foregroundStyle(.secondary)
                    Text(file?.lastPathComponent ?? "Drop a file here, or choose one")
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .foregroundStyle(file == nil ? .secondary : .primary)
                    Spacer()
                }
                HStack {
                    Button("Choose File…") { file = chooseURL(directory: false) }
                    Button("Paste Path") { if let url = pastedFileURL() { file = url } }
                    Spacer()
                }
                .disabled(viewModel.isBusy)
            }
            .padding(10)
            .frame(maxWidth: .infinity)
            .background(
                RoundedRectangle(cornerRadius: 8)
                    .strokeBorder(dropTargeted ? Color.accentColor : Color.secondary.opacity(0.3),
                                  style: StrokeStyle(lineWidth: dropTargeted ? 2 : 1, dash: [6]))
            )
            .onDrop(of: [.fileURL], isTargeted: $dropTargeted) { providers in
                guard !viewModel.isBusy, let provider = providers.first else { return false }
                _ = provider.loadObject(ofClass: URL.self) { url, _ in
                    if let url { DispatchQueue.main.async { file = url } }
                }
                return true
            }

            if mode == .token {
                TokenField(token: $token, disabled: viewModel.isBusy)
            } else {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Invite from receiver").font(.caption).foregroundStyle(.secondary)
                    TextField("envoix:…", text: $invite, axis: .vertical)
                        .textFieldStyle(.roundedBorder)
                        .lineLimit(1...3)
                        .disabled(viewModel.isBusy)
                }
            }

            TransferStatusView(viewModel: viewModel)

            Spacer()

            Button(action: primaryAction) {
                Text(primaryLabel)
                    .frame(maxWidth: .infinity)
            }
            .keyboardShortcut(.defaultAction)
            .controlSize(.large)
            .disabled(!canSend && !viewModel.isBusy)
        }
        .padding()
    }

    private var primaryLabel: String {
        if viewModel.isBusy { return "Cancel" }
        switch viewModel.phase {
        case .completed, .failed: return "Send Again"
        default: return "Send"
        }
    }

    private var canSend: Bool {
        guard file != nil else { return false }
        switch mode {
        case .token: return token.trimmed.count >= minTokenLength
        case .invite: return !invite.trimmed.isEmpty
        }
    }

    private func primaryAction() {
        if viewModel.isBusy {
            viewModel.cancel()
            return
        }
        guard let file else { return }
        switch mode {
        case .token:
            viewModel.startSendingWithToken(filePath: file.path, token: token.trimmed)
        case .invite:
            viewModel.startSendingWithInvite(filePath: file.path, invite: invite.trimmed)
        }
    }
}
