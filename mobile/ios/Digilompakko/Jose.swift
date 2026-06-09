import Foundation
import CryptoKit

enum WalletError: Error, LocalizedError {
    case noKey
    case keychain(OSStatus)
    case badResponse(String)
    case verification(String)

    var errorDescription: String? {
        switch self {
        case .noKey: return "No holder key"
        case .keychain(let s): return "Keychain error \(s)"
        case .badResponse(let m): return m
        case .verification(let m): return m
        }
    }
}

/// JSON Web Key (P-256 public key) used for `cnf`, OpenID4VCI proof headers, and verification.
struct JWK: Codable {
    var kty: String
    var crv: String
    var x: String
    var y: String
    var alg: String? = "ES256"
}

extension Data {
    /// base64url without padding.
    func base64url() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    init?(base64url string: String) {
        var s = string.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while s.count % 4 != 0 { s += "=" }
        self.init(base64Encoded: s)
    }
}

/// Minimal JOSE: ES256 JWT signing (via the Secure Enclave keystore) and JWS verification.
enum Jose {
    static func sha256url(_ s: String) -> String {
        Data(SHA256.hash(data: Data(s.utf8))).base64url()
    }

    /// Sign a compact JWT with ES256. The signature is produced inside the keystore (WSCD).
    static func signJWT(header: [String: Any], payload: [String: Any]) throws -> String {
        let h = try json(header).base64url()
        let p = try json(payload).base64url()
        let signingInput = "\(h).\(p)"
        let sig = try SecureKeyStore.shared.sign(Data(signingInput.utf8))
        return "\(signingInput).\(sig.base64url())"
    }

    /// Verify a compact JWS against a P-256 public JWK; returns the decoded payload on success.
    @discardableResult
    static func verifyJWS(_ compact: String, jwk: JWK) throws -> [String: Any] {
        let parts = compact.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 3 else { throw WalletError.verification("malformed JWS") }
        guard let x = Data(base64url: jwk.x), let y = Data(base64url: jwk.y),
              let sig = Data(base64url: parts[2]) else {
            throw WalletError.verification("bad key/signature encoding")
        }
        let pub = try P256.Signing.PublicKey(rawRepresentation: x + y)
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: sig)
        let signingInput = Data("\(parts[0]).\(parts[1])".utf8)
        guard pub.isValidSignature(signature, for: signingInput) else {
            throw WalletError.verification("signature invalid")
        }
        return try decodeJSON(parts[1])
    }

    /// Verify an OpenID4VP signed request object (JAR — RFC 9101).
    /// Checks header alg + typ, verifies the ES256 signature, then validates exp and aud.
    // MEDIUM-4: mobile wallet must validate alg, typ, exp, aud on JAR (HAIP §4.1, RFC 9101 §4)
    @discardableResult
    static func verifyRequestObject(_ compact: String, jwk: JWK, expectedAudience: String) throws -> [String: Any] {
        let parts = compact.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 3 else { throw WalletError.verification("malformed request object") }
        let header = try decodeJSON(parts[0])
        guard let alg = header["alg"] as? String, alg == "ES256" else {
            throw WalletError.verification("request object: alg must be ES256")
        }
        guard let typ = header["typ"] as? String, typ == "oauth-authz-req+jwt" else {
            throw WalletError.verification("request object: typ must be oauth-authz-req+jwt")
        }
        let payload = try verifyJWS(compact, jwk: jwk)
        guard let exp = payload["exp"] as? Double else {
            throw WalletError.verification("request object: missing exp")
        }
        guard exp > Date().timeIntervalSince1970 else {
            throw WalletError.verification("request object: expired")
        }
        guard let aud = payload["aud"] as? String, aud == expectedAudience else {
            throw WalletError.verification("request object: aud mismatch (expected \(expectedAudience))")
        }
        return payload
    }

    /// Read a JWT payload WITHOUT verifying (e.g. to discover `client_id` before fetching JWKS).
    static func decodeUnverifiedPayload(_ compact: String) throws -> [String: Any] {
        let parts = compact.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count >= 2 else { throw WalletError.verification("malformed JWT") }
        return try decodeJSON(parts[1])
    }

    // MARK: helpers
    private static func json(_ obj: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys])
    }
    private static func decodeJSON(_ b64url: String) throws -> [String: Any] {
        guard let d = Data(base64url: b64url),
              let obj = try JSONSerialization.jsonObject(with: d) as? [String: Any] else {
            throw WalletError.verification("bad JSON segment")
        }
        return obj
    }
}
