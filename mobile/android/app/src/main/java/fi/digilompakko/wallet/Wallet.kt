package fi.digilompakko.wallet

import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.BufferedReader
import java.net.HttpURLConnection
import java.net.URL

/**
 * Demo service endpoints. The Android emulator reaches the host machine via 10.0.2.2.
 * On a real device, set these to your machine's LAN IP.
 */
object Config {
    var issuerURL = "http://10.0.2.2:4001"
    var verifierURL = "http://10.0.2.2:4002"
}

data class StoredCredential(val sdJwt: String) {
    val vct: String get() = SdJwt.vct(sdJwt)
    val disclosures: List<SdJwt.Disclosure> get() = SdJwt.parse(sdJwt).second
}

/** Drives OpenID4VCI issuance and OpenID4VP presentation for SD-JWT VC, via the keystore. */
class WalletViewModel : ViewModel() {
    val credentials = mutableStateListOf<StoredCredential>()
    val status = mutableStateOf("")
    val lastResult = mutableStateOf("")
    val isHardwareBacked = mutableStateOf(false)

    init {
        SecureKeyStore.ensureKey()
        isHardwareBacked.value = SecureKeyStore.isStrongBoxBacked
    }

    fun receivePid() = viewModelScope.launch {
        try {
            status.value = "Requesting credential offer…"
            withContext(Dispatchers.IO) {
                val issuer = Config.issuerURL
                val offer = Http.post("$issuer/offer", JSONObject())
                val preAuth = offer.getJSONObject("grants")
                    .getJSONObject("urn:ietf:params:oauth:grant-type:pre-authorized_code")
                    .getString("pre-authorized_code")

                val token = Http.post("$issuer/token", JSONObject()
                    .put("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
                    .put("pre-authorized_code", preAuth))
                val accessToken = token.getString("access_token")
                val cNonce = token.getString("c_nonce")

                val proof = Jose.signJWT(
                    JSONObject().put("alg", "ES256").put("typ", "openid4vci-proof+jwt")
                        .put("jwk", SecureKeyStore.publicJWK().toJson()),
                    JSONObject().put("iat", System.currentTimeMillis() / 1000)
                        .put("nonce", cNonce).put("aud", issuer)
                )
                val cred = Http.post("$issuer/credential", JSONObject()
                    .put("format", "dc+sd-jwt")
                    .put("proof", JSONObject().put("proof_type", "jwt").put("jwt", proof)),
                    bearer = accessToken)
                val sdJwt = cred.getString("credential")
                withContext(Dispatchers.Main) {
                    credentials.add(StoredCredential(sdJwt))
                    status.value = "Stored ${SdJwt.vct(sdJwt)}"
                }
            }
        } catch (e: Exception) {
            status.value = "Error: ${e.message}"
        }
    }

    fun present(cred: StoredCredential, reveal: List<String>) = viewModelScope.launch {
        try {
            status.value = "Building presentation…"
            val result = withContext(Dispatchers.IO) {
                val verifier = Config.verifierURL
                val requestUri = Http.post("$verifier/presentation/request", JSONObject()).getString("request_uri")

                // Fetch + VERIFY the signed request object (JAR) before disclosing anything.
                val raw = Http.get(requestUri)
                val request = if (raw.has("request")) {
                    val jar = raw.getString("request")
                    val clientId = Jose.decodeUnverifiedPayload(jar).getString("client_id")
                    val jwks = Http.get("$clientId/jwks.json")
                    val key = JWK.from(jwks.getJSONArray("keys").getJSONObject(0))
                    // MEDIUM-4: verify alg, typ, exp, aud in addition to ES256 signature (HAIP §4.1)
                    Jose.verifyRequestObject(jar, key, "digilompakko-wallet")
                } else raw

                val clientId = request.getString("client_id")
                val nonce = request.getString("nonce")
                val responseUri = request.getString("response_uri")

                val vpToken = SdJwt.buildPresentation(cred.sdJwt, reveal, clientId, nonce)
                Http.post(responseUri, JSONObject().put("vp_token", vpToken))
            }
            lastResult.value = result.toString(2)
            status.value = if (result.optBoolean("valid")) "✓ Verified" else "✗ Rejected"
        } catch (e: Exception) {
            status.value = "Error: ${e.message}"
        }
    }
}

object Http {
    fun post(url: String, body: JSONObject, bearer: String? = null): JSONObject =
        request(url, "POST", body, bearer)

    fun get(url: String): JSONObject = request(url, "GET", null, null)

    private fun request(url: String, method: String, body: JSONObject?, bearer: String?): JSONObject {
        val conn = URL(url).openConnection() as HttpURLConnection
        conn.requestMethod = method
        conn.setRequestProperty("Accept", "application/json")
        bearer?.let { conn.setRequestProperty("Authorization", "Bearer $it") }
        if (body != null) {
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", "application/json")
            conn.outputStream.use { it.write(body.toString().toByteArray()) }
        }
        val stream = if (conn.responseCode in 200..299) conn.inputStream else conn.errorStream
        val text = stream.bufferedReader().use(BufferedReader::readText)
        return if (text.isBlank()) JSONObject() else JSONObject(text)
    }
}
