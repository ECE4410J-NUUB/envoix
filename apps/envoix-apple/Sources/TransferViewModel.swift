import Foundation
import EnvoixCore

/// Drives one send or receive operation and exposes its state to SwiftUI.
///
/// All `@Published` mutations happen on the main thread: user actions are
/// invoked from the UI, and core callbacks are marshaled to main by `Observer`.
final class TransferViewModel: ObservableObject {
    enum Phase: Equatable {
        case idle
        case waiting          // receiver: endpoint up, invite shown, awaiting sender
        case transferring
        case completed(bytes: UInt64)
        case failed(String)
    }

    @Published var phase: Phase = .idle
    @Published var invite: String = ""        // receiver only
    @Published var fileName: String = ""
    @Published var transferred: UInt64 = 0
    @Published var total: UInt64 = 0
    @Published var statusText: String = ""

    private var session: EnvoixSession?

    var progressFraction: Double {
        total > 0 ? Double(transferred) / Double(total) : 0
    }

    var isBusy: Bool {
        switch phase {
        case .waiting, .transferring: return true
        default: return false
        }
    }

    // MARK: User actions

    /// Receive on the local network using a shared token (mDNS auto-discovery).
    func startReceivingWithToken(outputDir: String, token: String) {
        start(phase: .waiting) { try $0.receiveMdns(outputDir: outputDir, token: token, observer: $1) }
    }

    /// Receive by publishing an invite the sender pastes/scans.
    func startReceivingWithInvite(outputDir: String) {
        start(phase: .waiting) { try $0.receive(outputDir: outputDir, observer: $1) }
    }

    /// Send on the local network using a shared token (mDNS auto-discovery).
    func startSendingWithToken(filePath: String, token: String) {
        start(phase: .transferring) { try $0.sendMdns(filePath: filePath, token: token, observer: $1) }
    }

    /// Send to the peer encoded in an invite string.
    func startSendingWithInvite(filePath: String, invite: String) {
        start(phase: .transferring) { try $0.sendInvite(invite: invite, filePath: filePath, observer: $1) }
    }

    func cancel() {
        session?.cancel()
    }

    /// Spins up a fresh session and launches `operation`, surfacing setup errors.
    private func start(phase: Phase, operation: (EnvoixSession, Observer) throws -> Void) {
        reset()
        let session = EnvoixSession()
        self.session = session
        self.phase = phase
        do {
            try operation(session, Observer(self))
        } catch {
            self.phase = .failed(error.localizedDescription)
        }
    }

    // MARK: Core callbacks (already on main via Observer)

    func handleInvite(_ invite: String) { self.invite = invite }

    func handleStarted(_ name: String, _ total: UInt64) {
        fileName = name
        self.total = total
        transferred = 0
        phase = .transferring
    }

    func handleProgress(_ transferred: UInt64, _ total: UInt64) {
        self.transferred = transferred
        self.total = total
    }

    func handleCompleted(_ bytes: UInt64) {
        transferred = total
        phase = .completed(bytes: bytes)
    }

    func handleFailed(_ reason: String) { phase = .failed(reason) }

    func handleStatus(_ message: String) { statusText = message }

    private func reset() {
        invite = ""
        fileName = ""
        transferred = 0
        total = 0
        statusText = ""
        phase = .idle
    }
}

/// Bridges core `TransferObserver` callbacks (delivered on Rust runtime threads)
/// onto the main thread before touching the view model.
final class Observer: TransferObserver, @unchecked Sendable {
    private weak var viewModel: TransferViewModel?

    init(_ viewModel: TransferViewModel) {
        self.viewModel = viewModel
    }

    func onInviteReady(invite: String) { hop { $0.handleInvite(invite) } }
    func onStarted(fileName: String, totalBytes: UInt64) { hop { $0.handleStarted(fileName, totalBytes) } }
    func onProgress(transferred: UInt64, total: UInt64) { hop { $0.handleProgress(transferred, total) } }
    func onCompleted(bytes: UInt64) { hop { $0.handleCompleted(bytes) } }
    func onFailed(reason: String) { hop { $0.handleFailed(reason) } }
    func onStatus(message: String) { hop { $0.handleStatus(message) } }

    private func hop(_ body: @escaping (TransferViewModel) -> Void) {
        DispatchQueue.main.async { [weak viewModel] in
            if let viewModel { body(viewModel) }
        }
    }
}
