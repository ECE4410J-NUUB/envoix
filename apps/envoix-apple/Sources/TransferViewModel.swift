import Foundation
import Combine
import EnvoixCore

/// App-wide shared state: the two long-lived transfer view models (one per tab).
///
/// Both the main window and the menu-bar popover observe the same instances, so
/// status stays in sync everywhere. Re-emitting the children's `objectWillChange`
/// lets a view that observes only `AppModel` still update on transfer progress.
final class AppModel: ObservableObject {
    static let shared = AppModel()

    let receive = TransferViewModel()
    let send = TransferViewModel()

    private var cancellables = Set<AnyCancellable>()

    private init() {
        for vm in [receive, send] {
            vm.objectWillChange
                .sink { [weak self] in self?.objectWillChange.send() }
                .store(in: &cancellables)
        }
    }

    /// True while either side has a transfer in flight.
    var isActive: Bool { receive.isBusy || send.isBusy }
}

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
    @Published var peerAddress: String = ""   // raw IP-bearing address, hidden by default
    @Published var bytesPerSec: Double = 0    // rolling average, 0 until measurable
    @Published var completedFileURL: URL?     // receiver only: where the file landed

    private var session: EnvoixSession?
    private var destinationDir: String?       // receiver only
    private var rate = RateTracker()
    private var suppressNextFailure = false

    var progressFraction: Double {
        total > 0 ? Double(transferred) / Double(total) : 0
    }

    /// Seconds left at the current average rate, or nil if not yet estimable.
    var etaSeconds: Double? {
        guard bytesPerSec > 0, total > transferred else { return nil }
        return Double(total - transferred) / bytesPerSec
    }

    var isBusy: Bool {
        switch phase {
        case .waiting, .transferring: return true
        default: return false
        }
    }

    // MARK: User actions

    /// Receive on the local network using a shared token (mDNS auto-discovery).
    func startReceivingWithToken(outputDir: String, token: String, settings: EnvoixRuntimeSettings) {
        destinationDir = outputDir
        start(settings: settings, phase: .waiting) { try $0.receiveMdns(outputDir: outputDir, token: token, observer: $1) }
    }

    /// Receive by publishing an invite the sender pastes/scans.
    func startReceivingWithInvite(outputDir: String, settings: EnvoixRuntimeSettings) {
        destinationDir = outputDir
        start(settings: settings, phase: .waiting) { try $0.receive(outputDir: outputDir, observer: $1) }
    }

    /// Send on the local network using a shared token (mDNS auto-discovery).
    func startSendingWithToken(filePath: String, token: String, settings: EnvoixRuntimeSettings) {
        destinationDir = nil
        start(settings: settings, phase: .transferring) { try $0.sendMdns(filePath: filePath, token: token, observer: $1) }
    }

    /// Send to the peer encoded in an invite string.
    func startSendingWithInvite(filePath: String, invite: String, settings: EnvoixRuntimeSettings) {
        destinationDir = nil
        start(settings: settings, phase: .transferring) { try $0.sendInvite(invite: invite, filePath: filePath, observer: $1) }
    }

    func cancel() {
        suppressNextFailure = true
        session?.cancel()
        reset()
        statusText = "Canceled"
    }

    /// Spins up a fresh session and launches `operation`, surfacing setup errors.
    private func start(
        settings: EnvoixRuntimeSettings,
        phase: Phase,
        operation: (EnvoixSession, Observer) throws -> Void
    ) {
        suppressNextFailure = false
        reset()
        self.phase = phase
        do {
            let session = try EnvoixSession.newWithSettings(settings: settings)
            self.session = session
            try operation(session, Observer(self))
        } catch {
            self.phase = .failed(friendlyError(error.localizedDescription))
        }
    }

    // MARK: Core callbacks (already on main via Observer)

    func handleInvite(_ invite: String) { self.invite = invite }

    func handleStarted(_ name: String, _ total: UInt64) {
        fileName = name
        self.total = total
        transferred = 0
        rate.reset()
        bytesPerSec = 0
        phase = .transferring
    }

    func handleProgress(_ transferred: UInt64, _ total: UInt64) {
        self.transferred = transferred
        self.total = total
        bytesPerSec = rate.record(transferred)
    }

    func handleCompleted(_ bytes: UInt64) {
        transferred = total
        bytesPerSec = 0
        if let dir = destinationDir, !fileName.isEmpty {
            completedFileURL = URL(fileURLWithPath: dir).appendingPathComponent(fileName)
        }
        phase = .completed(bytes: bytes)
    }

    func handleFailed(_ reason: String) {
        if suppressNextFailure {
            suppressNextFailure = false
            reset()
            statusText = "Canceled"
            return
        }
        phase = .failed(friendlyError(reason))
    }

    /// The core echoes the bound peer as `"address: <descriptor>"`, which
    /// carries the real IP. Keep that out of the general status line and stash
    /// it separately so the UI can gate it behind an explicit reveal.
    func handleStatus(_ message: String) {
        let prefix = "address: "
        if message.hasPrefix(prefix) {
            peerAddress = String(message.dropFirst(prefix.count))
        } else {
            statusText = message
        }
    }

    private func reset() {
        invite = ""
        fileName = ""
        transferred = 0
        total = 0
        statusText = ""
        peerAddress = ""
        bytesPerSec = 0
        completedFileURL = nil
        rate.reset()
        phase = .idle
    }
}

/// Rolling-window throughput estimate: average speed over roughly the last few
/// seconds, which absorbs short bursts/stalls without lagging the whole transfer.
private struct RateTracker {
    private struct Sample { let time: TimeInterval; let bytes: UInt64 }
    private var samples: [Sample] = []
    private let window: TimeInterval = 3

    mutating func reset() { samples.removeAll() }

    /// Records a cumulative byte count, returns the current bytes/sec estimate.
    mutating func record(_ bytes: UInt64) -> Double {
        let now = ProcessInfo.processInfo.systemUptime
        samples.append(Sample(time: now, bytes: bytes))
        samples.removeAll { now - $0.time > window }
        guard let first = samples.first, samples.count > 1 else { return 0 }
        let dt = now - first.time
        guard dt > 0 else { return 0 }
        return Double(bytes - first.bytes) / dt
    }
}

/// Maps common raw failure strings to friendlier English; passes others through.
func friendlyError(_ reason: String) -> String {
    let lower = reason.lowercased()
    if lower.contains("timed out") || lower.contains("timeout") || lower.contains("deadline") {
        return "Couldn't reach the other device. Make sure both are on the same Wi-Fi network and the token matches."
    }
    if lower.contains("no peer") || lower.contains("not found") || lower.contains("no route") {
        return "No device found. Check that the other side is running and the token or invite is correct."
    }
    if lower.contains("expired") {
        return "This invite has expired. Ask the receiver to generate a new one."
    }
    if lower.contains("permission") || lower.contains("denied") {
        return "Access was denied. Check the destination folder permissions and local-network access."
    }
    return reason
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
