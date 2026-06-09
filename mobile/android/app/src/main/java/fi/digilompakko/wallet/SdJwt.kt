package fi.digilompakko.wallet

import org.json.JSONArray
import org.json.JSONObject

/**
 * SD-JWT VC handling on the holder side: parse an issued credential, enumerate disclosable claims,
 * and build a presentation (chosen disclosures + Key Binding JWT). Mirrors `packages/core`.
 */
object SdJwt {
    data class Disclosure(val encoded: String, val name: String, val value: String)

    fun parse(compact: String): Pair<String, List<Disclosure>> {
        val parts = compact.split("~").toMutableList()
        val jws = parts.removeAt(0)
        if (parts.isNotEmpty() && parts.last() == "") parts.removeAt(parts.size - 1)
        val discs = parts.mapNotNull { decodeDisclosure(it) }
        return jws to discs
    }

    fun payload(compact: String): JSONObject =
        runCatching { Jose.decodeUnverifiedPayload(compact.split("~").first()) }.getOrDefault(JSONObject())

    fun vct(compact: String): String = payload(compact).optString("vct", "credential")

    /** Build an OpenID4VP presentation revealing only `reveal`, with a KB-JWT over nonce+aud. */
    fun buildPresentation(issued: String, reveal: List<String>, audience: String, nonce: String): String {
        val (jws, disclosures) = parse(issued)
        val kept = disclosures.filter { reveal.contains(it.name) }.map { it.encoded }
        val head = (listOf(jws) + kept).joinToString("~") + "~"
        val sdHash = Jose.sha256url(head)
        val kbJwt = Jose.signJWT(
            JSONObject().put("alg", "ES256").put("typ", "kb+jwt"),
            JSONObject()
                .put("iat", System.currentTimeMillis() / 1000)
                .put("nonce", nonce).put("aud", audience).put("sd_hash", sdHash)
        )
        return head + kbJwt
    }

    private fun decodeDisclosure(encoded: String): Disclosure? {
        if (encoded.isEmpty()) return null
        return runCatching {
            val arr = JSONArray(String(b64urlDecode(encoded)))
            if (arr.length() != 3) return null
            Disclosure(encoded, arr.getString(1), arr.get(2).toString())
        }.getOrNull()
    }
}
