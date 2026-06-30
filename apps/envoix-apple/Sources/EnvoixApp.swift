import SwiftUI

@main
struct EnvoixApp: App {
    @StateObject private var model = AppModel.shared

    var body: some Scene {
        WindowGroup(id: "main") {
            ContentView()
                .environmentObject(model)
        }
        .windowResizability(.contentMinSize)

        // Menu-bar presence: keeps the app alive after the window is closed and
        // gives a quick status popover. `.window` style shows SwiftUI content.
        MenuBarExtra {
            MenuBarView()
                .environmentObject(model)
        } label: {
            Image(systemName: model.isActive ? "arrow.up.arrow.down.circle.fill"
                                              : "arrow.up.arrow.down.circle")
        }
        .menuBarExtraStyle(.window)
    }
}
