import Foundation

/// Demo service endpoints. The iOS Simulator can reach the Mac's localhost directly.
/// On a real device, set these to your machine's LAN IP (and allow it in Info.plist ATS).
enum Config {
    static var issuerURL = "http://localhost:4001"
    static var verifierURL = "http://localhost:4002"
}

struct StoredCredential: Identifiable {
    let id = UUID()
    let sdJwt: String
    var vct: String { SdJwt.vct(sdJwt) }
    var disclosures: [SdJwt.Disclosure] { SdJwt.parse(sdJwt).disclosures }
}

/// Drives the OpenID4VCI issuance and OpenID4VP presentation flows for SD-JWT VC, signing
/// everything through the Secure Enclave keystore.
@MainActor
final class WalletModel: ObservableObject {
    @Published var credentials: [StoredCredential] = []
    @Published var status: String = ""
    @Published var lastResult: String = ""
    @Published var isHardwareBacked = false

    init() {
        try? SecureKeyStore.shared.ensureKey()
        isHardwareBacked = SecureKeyStore.shared.isHardwareBacked
    }

    // MARK: - OpenID4VCI (pre-authorized code flow)

    func receivePid() async {
        do {
            status = "Requesting credential offer…"
            let issuer = Config.issuerURL
            let offer = try await postJSON("\(issuer)/offer", body: [:])
            let grants = offer["grants"] as? [String: Any]
            let preAuthGrant = grants?["urn:ietf:params:oauth:grant-type:pre-authorized_code"] as? [String: Any]
            let preAuth = preAuthGrant?["pre-authorized_code"] as? String ?? ""

            let token = try await postJSON("\(issuer)/token", body: [
                "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                "pre-authorized_code": preAuth,
            ])
            let accessToken = token["access_token"] as? String ?? ""
            let cNonce = token["c_nonce"] as? String ?? ""

            // Proof of possession, signed inside the Secure Enclave.
            let jwk = try SecureKeyStore.shared.publicJWK()
            let proof = try Jose.signJWT(
                header: ["alg": "ES256", "typ": "openid4vci-proof+jwt", "jwk": jwk.dict()],
                payload: ["iat": Int(Date().timeIntervalSince1970), "nonce": cNonce, "aud": issuer]
            )

            let cred = try await postJSON("\(issuer)/credential",
                body: ["format": "dc+sd-jwt", "proof": ["proof_type": "jwt", "jwt": proof]],
                bearer: accessToken)
            guard let sdJwt = cred["credential"] as? String else { throw WalletError.badResponse("no credential") }

            credentials.append(StoredCredential(sdJwt: sdJwt))
            status = "Stored \(SdJwt.vct(sdJwt))"
        } catch {
            status = "Error: \(error.localizedDescription)"
        }
    }

    // MARK: - OpenID4VP (presentation with signed request object)

    func present(credential: StoredCredential, reveal: [String]) async {
        do {
            status = "Building presentation…"
            let verifier = Config.verifierURL
            let req = try await postJSON("\(verifier)/presentation/request", body: [:])
            let requestUri = req["request_uri"] as? String ?? ""

            // Fetch and VERIFY the signed request object (JAR) before disclosing anything.
            let raw = try await getJSON(requestUri)
            let request: [String: Any]
            if let jar = raw["request"] as? String {
                let clientId = (try Jose.decodeUnverifiedPayload(jar)["client_id"] as? String) ?? ""
                let jwks = try await getJSON("\(clientId)/jwks.json")
                guard let keys = jwks["keys"] as? [[String: Any]], let k = keys.first,
                      let jwk = JWK(dict: k) else { throw WalletError.verification("no RP key") }
                // MEDIUM-4: verify alg, typ, exp, aud in addition to the ES256 signature (HAIP §4.1)
                request = try Jose.verifyRequestObject(jar, jwk: jwk, expectedAudience: "digilompakko-wallet")
            } else {
                request = raw
            }

            let clientId = request["client_id"] as? String ?? ""
            let nonce = request["nonce"] as? String ?? ""
            let responseUri = request["response_uri"] as? String ?? ""

            let vpToken = try SdJwt.buildPresentation(issued: credential.sdJwt, reveal: reveal, audience: clientId, nonce: nonce)
            let result = try await postJSON(responseUri, body: ["vp_token": vpToken])

            lastResult = prettyJSON(result)
            status = (result["valid"] as? Bool == true) ? "✓ Verified" : "✗ Rejected"
        } catch {
            status = "Error: \(error.localizedDescription)"
        }
    }

    // MARK: - HTTP helpers

    private func postJSON(_ url: String, body: [String: Any], bearer: String? = nil) async throws -> [String: Any] {
        var req = URLRequest(url: URL(string: url)!)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let bearer { req.setValue("Bearer \(bearer)", forHTTPHeaderField: "Authorization") }
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, _) = try await URLSession.shared.data(for: req)
        return (try? JSONSerialization.jsonObject(with: data) as? [String: Any]) ?? [:]
    }

    private func getJSON(_ url: String) async throws -> [String: Any] {
        let (data, _) = try await URLSession.shared.data(from: URL(string: url)!)
        return (try? JSONSerialization.jsonObject(with: data) as? [String: Any]) ?? [:]
    }

    private func prettyJSON(_ obj: [String: Any]) -> String {
        guard let d = try? JSONSerialization.data(withJSONObject: obj, options: [.prettyPrinted, .sortedKeys]),
              let s = String(data: d, encoding: .utf8) else { return "\(obj)" }
        return s
    }
}

extension JWK {
    func dict() -> [String: Any] { ["kty": kty, "crv": crv, "x": x, "y": y] }
    init?(dict: [String: Any]) {
        guard let kty = dict["kty"] as? String, let crv = dict["crv"] as? String,
              let x = dict["x"] as? String, let y = dict["y"] as? String else { return nil }
        self.init(kty: kty, crv: crv, x: x, y: y)
    }
}
