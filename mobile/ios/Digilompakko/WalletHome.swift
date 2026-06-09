import SwiftUI

private let brand = Color(red: 0.05, green: 0.27, blue: 0.55)

struct WalletHome: View {
    @EnvironmentObject var model: WalletModel
    @State private var presenting: StoredCredential?

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    keyBanner
                    if model.credentials.isEmpty {
                        emptyState
                    } else {
                        ForEach(model.credentials) { cred in
                            CredentialCard(cred: cred) { presenting = cred }
                        }
                    }
                    if !model.status.isEmpty {
                        Text(model.status).font(.footnote).foregroundStyle(.secondary)
                    }
                }
                .padding()
            }
            .navigationTitle("Digilompakko")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        Task { await model.receivePid() }
                    } label: { Label("Receive", systemImage: "plus.circle.fill") }
                }
            }
            .sheet(item: $presenting) { cred in
                PresentSheet(cred: cred).environmentObject(model)
            }
        }
        .tint(brand)
    }

    private var keyBanner: some View {
        HStack(spacing: 10) {
            Image(systemName: model.isHardwareBacked ? "lock.shield.fill" : "lock.shield")
                .foregroundStyle(model.isHardwareBacked ? .green : .orange)
            VStack(alignment: .leading, spacing: 2) {
                Text(model.isHardwareBacked ? "Secure Enclave key" : "Software key (Simulator)")
                    .font(.subheadline.weight(.semibold))
                Text("Holder key · ES256 / P-256").font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding()
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 14))
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "wallet.pass").font(.system(size: 44)).foregroundStyle(brand.opacity(0.6))
            Text("No credentials yet").font(.headline)
            Text("Tap Receive to get your PID from the demo issuer.")
                .font(.subheadline).foregroundStyle(.secondary).multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity).padding(.vertical, 48)
    }
}

struct CredentialCard: View {
    let cred: StoredCredential
    let onPresent: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Image(systemName: "person.text.rectangle.fill").font(.title2)
                Spacer()
                Text("SD-JWT VC").font(.caption2.weight(.bold))
                    .padding(.horizontal, 8).padding(.vertical, 4)
                    .background(.white.opacity(0.2), in: Capsule())
            }
            Text(title).font(.title3.weight(.bold))
            Text(cred.vct).font(.caption).opacity(0.8)
            HStack {
                Text("\(cred.disclosures.count) attributes").font(.caption)
                Spacer()
                Button(action: onPresent) {
                    Text("Present").font(.subheadline.weight(.semibold))
                        .padding(.horizontal, 14).padding(.vertical, 7)
                        .background(.white.opacity(0.25), in: Capsule())
                }
            }
        }
        .foregroundStyle(.white)
        .padding(18)
        .background(
            LinearGradient(colors: [brand, brand.opacity(0.75)], startPoint: .topLeading, endPoint: .bottomTrailing),
            in: RoundedRectangle(cornerRadius: 18)
        )
        .shadow(color: brand.opacity(0.3), radius: 10, y: 6)
    }

    private var title: String {
        cred.vct.contains("pid") ? "Person Identification" : cred.vct
    }
}
