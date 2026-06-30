import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        TabView {
            ReceiveView(viewModel: model.receive)
                .tabItem { Label("Receive", systemImage: "tray.and.arrow.down") }
            SendView(viewModel: model.send)
                .tabItem { Label("Send", systemImage: "paperplane") }
        }
        .padding()
        .frame(minWidth: 460, minHeight: 540)
    }
}
