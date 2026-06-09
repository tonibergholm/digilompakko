import Foundation

/// SD-JWT VC handling on the holder side: parse an issued credential, enumerate its
/// selectively-disclosable claims, and build a presentation (chosen disclosures + Key Binding JWT).
/// Mirrors `packages/core/src/sd-jwt.ts`.
enum SdJwt {
    struct Disclosure: Identifiable {
        let id = UUID()
        let encoded: String
        let name: String
        let value: Any
        var displayValue: String { String(describing: value) }
    }

    /// Split `<jws>~<disclosure>~...~` into its JWS and disclosures (ignores a trailing KB-JWT slot).
    static func parse(_ compact: String) -> (jws: String, disclosures: [Disclosure]) {
        var parts = compact.components(separatedBy: "~")
        let jws = parts.removeFirst()
        if parts.last == "" { parts.removeLast() } // trailing ~ on issued form
        let discs = parts.compactMap(decodeDisclosure)
        return (jws, discs)
    }

    /// Issuer-signed payload (unverified) — used to read `vct`, `iss`, `exp`, etc. for display.
    static func payload(_ compact: String) -> [String: Any] {
        let jws = compact.components(separatedBy: "~").first ?? compact
        return (try? Jose.decodeUnverifiedPayload(jws)) ?? [:]
    }

    static func vct(_ compact: String) -> String {
        (payload(compact)["vct"] as? String) ?? "credential"
    }

    /// Build an OpenID4VP presentation revealing only `reveal`, with a KB-JWT over nonce+aud.
    static func buildPresentation(issued: String, reveal: [String], audience: String, nonce: String) throws -> String {
        let (jws, disclosures) = parse(issued)
        let kept = disclosures.filter { reveal.contains($0.name) }.map { $0.encoded }
        let head = ([jws] + kept).joined(separator: "~") + "~"
        let sdHash = Jose.sha256url(head)
        let kbJwt = try Jose.signJWT(
            header: ["alg": "ES256", "typ": "kb+jwt"],
            payload: ["iat": Int(Date().timeIntervalSince1970), "nonce": nonce, "aud": audience, "sd_hash": sdHash]
        )
        return head + kbJwt
    }

    private static func decodeDisclosure(_ encoded: String) -> Disclosure? {
        guard !encoded.isEmpty, let data = Data(base64url: encoded),
              let arr = try? JSONSerialization.jsonObject(with: data) as? [Any],
              arr.count == 3, let name = arr[1] as? String else { return nil }
        return Disclosure(encoded: encoded, name: name, value: arr[2])
    }
}
