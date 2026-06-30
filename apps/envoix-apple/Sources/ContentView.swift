import SwiftUI

struct ContentView: View {
    var body: some View {
        TabView {
            ReceiveView()
                .tabItem { Label("Receive", systemImage: "tray.and.arrow.down") }
            SendView()
                .tabItem { Label("Send", systemImage: "paperplane") }
        }
        .padding()
        .frame(width: 440, height: 520)
    }
}
