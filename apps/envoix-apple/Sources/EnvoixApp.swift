import SwiftUI

@main
struct EnvoixApp: App {
    @StateObject private var model = AppModel.shared
    @AppStorage("envoix.language") private var language = "en"

    var body: some Scene {
        WindowGroup(id: "main") {
            ContentView()
                .environmentObject(model)
                .environment(\.appLanguage, language)
        }
        .windowResizability(.contentMinSize)
        .defaultSize(width: 980, height: 720)

        // Menu-bar presence: keeps the app alive after the window is closed and
        // gives a quick status popover. `.window` style shows SwiftUI content.
        MenuBarExtra {
            MenuBarView()
                .environmentObject(model)
                .environment(\.appLanguage, language)
        } label: {
            Image(systemName: model.isActive ? "arrow.up.arrow.down.circle.fill"
                                              : "arrow.up.arrow.down.circle")
        }
        .menuBarExtraStyle(.window)
    }
}
