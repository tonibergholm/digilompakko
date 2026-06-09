import Foundation
import CryptoKit
import Security

/// A P-256 (ES256) signing key whose private material is held in the **Secure Enclave** — the iOS
/// WSCD. The private key never leaves hardware; we only ever ask the Enclave to sign.
///
/// The Secure Enclave is unavailable on the iOS Simulator, so we transparently fall back to a
/// software P-256 key there. On device, keys are hardware-backed.
final class SecureKeyStore {
    static let shared = SecureKeyStore()

    private let keychainTag = "fi.digilompakko.wallet.holderkey"
    private var enclaveKey: SecureEnclave.P256.Signing.PrivateKey?
    private var softwareKey: P256.Signing.PrivateKey?

    var isHardwareBacked: Bool { enclaveKey != nil }

    private init() {
        load()
    }

    /// Ensure a holder key exists, creating one (hardware-backed where possible) on first run.
    func ensureKey() throws {
        if enclaveKey != nil || softwareKey != nil { return }
        if SecureEnclave.isAvailable {
            let access = try accessControl()
            let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
            try persist(key.dataRepresentation)
            enclaveKey = key
        } else {
            // Simulator / no-Enclave fallback (clearly not production hardware).
            let key = P256.Signing.PrivateKey()
            try persist(key.rawRepresentation)
            softwareKey = key
        }
    }

    /// The holder public key as a JWK (for `cnf`, OpenID4VCI proof header, etc.).
    func publicJWK() throws -> JWK {
        let pub: P256.Signing.PublicKey
        if let k = enclaveKey { pub = k.publicKey } else if let k = softwareKey { pub = k.publicKey }
        else { throw WalletError.noKey }
        let raw = pub.rawRepresentation // 64 bytes: x(32) || y(32)
        return JWK(kty: "EC", crv: "P-256",
                   x: raw.prefix(32).base64url(), y: raw.suffix(32).base64url())
    }

    /// Sign `data` with ES256, returning a raw r||s (64-byte) JOSE signature.
    func sign(_ data: Data) throws -> Data {
        if let k = enclaveKey { return try k.signature(for: data).rawRepresentation }
        if let k = softwareKey { return try k.signature(for: data).rawRepresentation }
        throw WalletError.noKey
    }

    // MARK: - Persistence (the Enclave/raw key blob is stored in the Keychain)

    private func accessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage], &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return ac
    }

    private func persist(_ blob: Data) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: keychainTag,
        ]
        SecItemDelete(query as CFDictionary)
        var add = query
        add[kSecValueData as String] = blob
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else { throw WalletError.keychain(status) }
    }

    private func load() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: keychainTag,
            kSecReturnData as String: true,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let blob = item as? Data else { return }
        if SecureEnclave.isAvailable,
           let k = try? SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob) {
            enclaveKey = k
        } else if let k = try? P256.Signing.PrivateKey(rawRepresentation: blob) {
            softwareKey = k
        }
    }
}
