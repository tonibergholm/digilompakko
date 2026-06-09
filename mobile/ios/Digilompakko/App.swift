import SwiftUI

@main
struct DigilompakkoApp: App {
    @StateObject private var model = WalletModel()
    var body: some Scene {
        WindowGroup {
            WalletHome().environmentObject(model)
        }
    }
}
