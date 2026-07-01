#if DEBUG
import SwiftUI

enum PreviewFixtures {
    static let demoInvite = "envoix:demo-invite-token-for-preview-only"

    static func idle() -> TransferViewModel {
        TransferViewModel()
    }

    static func waitingForSender() -> TransferViewModel {
        let viewModel = TransferViewModel()
        viewModel.phase = .waiting
        viewModel.invite = demoInvite
        viewModel.statusText = "Invite ready. Waiting for sender."
        return viewModel
    }

    static func transferring(name: String = "design-review.pdf") -> TransferViewModel {
        let viewModel = TransferViewModel()
        viewModel.handleStarted(name, 240_000_000)
        viewModel.transferred = 92_000_000
        viewModel.bytesPerSec = 12_400_000
        return viewModel
    }

    static func completedReceive() -> TransferViewModel {
        let viewModel = TransferViewModel()
        viewModel.fileName = "field-notes.zip"
        viewModel.total = 48_000_000
        viewModel.transferred = 48_000_000
        viewModel.completedFileURL = URL(fileURLWithPath: "/Users/demo/Downloads/field-notes.zip")
        viewModel.phase = .completed(bytes: 48_000_000)
        return viewModel
    }

    static func failed() -> TransferViewModel {
        let viewModel = TransferViewModel()
        viewModel.phase = .failed("No device found. Check that the other side is running and the token or invite is correct.")
        return viewModel
    }
}

private struct PreviewScreen<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        ZStack {
            Theme.bg.ignoresSafeArea()
            content
                .environmentObject(AppModel.shared)
                .padding(16)
                .frame(width: 520, height: 720)
        }
    }
}

#Preview("App Shell") {
    ContentView()
        .environmentObject(AppModel.shared)
        .frame(width: 960, height: 720)
}

#Preview("Send - Progress") {
    PreviewScreen {
        SendView(viewModel: PreviewFixtures.transferring())
    }
}

#Preview("Receive - Invite") {
    PreviewScreen {
        ReceiveView(viewModel: PreviewFixtures.waitingForSender())
    }
}

#Preview("Receive - Completed") {
    PreviewScreen {
        ReceiveView(viewModel: PreviewFixtures.completedReceive())
    }
}

#Preview("Status - Failed") {
    PreviewScreen {
        TransferStatusView(viewModel: PreviewFixtures.failed())
    }
}
#endif
