import SwiftUI
import AppKit

/// Compact status shown in the menu-bar popover. Mirrors the live transfer state
/// and offers a one-click way to bring the main window forward.
struct MenuBarView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Envoix").font(.headline)

            row(title: "Receiving", vm: model.receive)
            row(title: "Sending", vm: model.send)

            Divider()

            Button("Open Envoix") {
                openWindow(id: "main")
                NSApp.activate(ignoringOtherApps: true)
            }
            Button("Quit Envoix") { NSApp.terminate(nil) }
        }
        .padding(14)
        .frame(width: 240)
    }

    @ViewBuilder private func row(title: String, vm: TransferViewModel) -> some View {
        HStack {
            Text(title).foregroundStyle(.secondary)
            Spacer()
            Text(summary(vm)).font(.callout.monospacedDigit())
        }
    }

    private func summary(_ vm: TransferViewModel) -> String {
        switch vm.phase {
        case .idle: return "Idle"
        case .waiting: return "Waiting…"
        case .transferring:
            let pct = Int((vm.progressFraction * 100).rounded())
            return vm.bytesPerSec > 0 ? "\(pct)% · \(rateString(vm.bytesPerSec))" : "\(pct)%"
        case .completed: return "Done"
        case .failed: return "Failed"
        }
    }
}
