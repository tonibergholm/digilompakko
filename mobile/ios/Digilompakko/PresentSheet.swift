import SwiftUI

private let brand = Color(red: 0.05, green: 0.27, blue: 0.55)

/// Consent + selective-disclosure screen: the user picks exactly which attributes to share.
struct PresentSheet: View {
    @EnvironmentObject var model: WalletModel
    @Environment(\.dismiss) private var dismiss
    let cred: StoredCredential

    @State private var selected: Set<String> = []
    @State private var busy = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("Choose what to share with the relying party. Only the attributes you select are disclosed; everything else stays private.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                Section("Attributes") {
                    ForEach(cred.disclosures) { d in
                        Toggle(isOn: binding(for: d.name)) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(d.name).font(.body)
                                Text(d.displayValue).font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                }
                if !model.lastResult.isEmpty {
                    Section("Verifier result") {
                        Text(model.lastResult).font(.system(.caption, design: .monospaced))
                    }
                }
            }
            .navigationTitle("Present")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Close") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button {
                        busy = true
                        Task {
                            await model.present(credential: cred, reveal: Array(selected))
                            busy = false
                        }
                    } label: { busy ? AnyView(ProgressView()) : AnyView(Text("Share").bold()) }
                    .disabled(selected.isEmpty || busy)
                }
            }
            .onAppear { if selected.isEmpty { selected = Set(cred.disclosures.map(\.name)) } }
            .tint(brand)
        }
    }

    private func binding(for name: String) -> Binding<Bool> {
        Binding(get: { selected.contains(name) },
                set: { $0 ? selected.insert(name) : selected.remove(name) })
    }
}
