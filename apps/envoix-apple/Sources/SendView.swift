import SwiftUI

struct SendView: View {
    @StateObject private var viewModel = TransferViewModel()
    @State private var file: URL?
    @AppStorage("envoix.token") private var token: String = ""
    @State private var invite: String = ""
    @State private var mode: PairingMode = .token

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

            HStack {
                Text(file?.lastPathComponent ?? "No file chosen")
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .foregroundStyle(file == nil ? .secondary : .primary)
                Spacer()
                Button("Choose File…") { file = chooseURL(directory: false) }
                    .disabled(viewModel.isBusy)
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
                Text(viewModel.isBusy ? "Cancel" : "Send")
                    .frame(maxWidth: .infinity)
            }
            .keyboardShortcut(.defaultAction)
            .controlSize(.large)
            .disabled(!canSend && !viewModel.isBusy)
        }
        .padding()
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
