package fi.digilompakko.wallet

import android.util.Base64
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec

data class JWK(val kty: String, val crv: String, val x: String, val y: String, val alg: String = "ES256") {
    fun toJson(): JSONObject = JSONObject().put("kty", kty).put("crv", crv).put("x", x).put("y", y)
    companion object {
        fun from(o: JSONObject) = JWK(o.getString("kty"), o.getString("crv"), o.getString("x"), o.getString("y"))
    }
}

fun b64url(b: ByteArray): String = Base64.encodeToString(b, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
fun b64urlDecode(s: String): ByteArray = Base64.decode(s, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

/** Minimal JOSE: ES256 JWT signing (via the keystore) and JWS verification. */
object Jose {
    fun sha256url(s: String): String =
        b64url(MessageDigest.getInstance("SHA-256").digest(s.toByteArray()))

    /** Sign a compact JWT with ES256, signed inside the keystore (WSCD). */
    fun signJWT(header: JSONObject, payload: JSONObject): String {
        val h = b64url(header.toString().toByteArray())
        val p = b64url(payload.toString().toByteArray())
        val signingInput = "$h.$p"
        val sig = SecureKeyStore.sign(signingInput.toByteArray())
        return "$signingInput.${b64url(sig)}"
    }

    /** Verify a compact JWS against a P-256 public JWK; returns the payload on success. */
    fun verifyJWS(compact: String, jwk: JWK): JSONObject {
        val parts = compact.split(".")
        require(parts.size == 3) { "malformed JWS" }
        val pub = publicKey(jwk)
        val der = joseToDer(b64urlDecode(parts[2]))
        val verifier = Signature.getInstance("SHA256withECDSA").apply { initVerify(pub) }
        verifier.update("${parts[0]}.${parts[1]}".toByteArray())
        require(verifier.verify(der)) { "signature invalid" }
        return JSONObject(String(b64urlDecode(parts[1])))
    }

    /** Read a JWT payload WITHOUT verifying (e.g. to find client_id before fetching JWKS). */
    fun decodeUnverifiedPayload(compact: String): JSONObject {
        val parts = compact.split(".")
        require(parts.size >= 2) { "malformed JWT" }
        return JSONObject(String(b64urlDecode(parts[1])))
    }

    private fun publicKey(jwk: JWK): java.security.PublicKey {
        val params = AlgorithmParameters.getInstance("EC").apply {
            init(ECGenParameterSpec("secp256r1"))
        }.getParameterSpec(ECParameterSpec::class.java)
        val point = ECPoint(BigInteger(1, b64urlDecode(jwk.x)), BigInteger(1, b64urlDecode(jwk.y)))
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, params))
    }
}

/** ECDSA DER (SEQUENCE{INTEGER r, INTEGER s}) -> raw r||s, each `len` bytes. */
fun derToJose(der: ByteArray, len: Int): ByteArray {
    require(der[0].toInt() == 0x30) { "bad DER" }
    var idx = 2
    require(der[idx].toInt() == 0x02); idx++
    val rLen = der[idx].toInt(); idx++
    val r = BigInteger(der.copyOfRange(idx, idx + rLen)); idx += rLen
    require(der[idx].toInt() == 0x02); idx++
    val sLen = der[idx].toInt(); idx++
    val s = BigInteger(der.copyOfRange(idx, idx + sLen))
    return r.to32Bytes() + s.to32Bytes()
}

/** raw r||s -> ECDSA DER. */
fun joseToDer(jose: ByteArray): ByteArray {
    val r = BigInteger(1, jose.copyOfRange(0, 32)).toByteArray()
    val s = BigInteger(1, jose.copyOfRange(32, 64)).toByteArray()
    val seqLen = 2 + r.size + 2 + s.size
    return ByteArrayOutputStream().apply {
        write(0x30); write(seqLen)
        write(0x02); write(r.size); write(r)
        write(0x02); write(s.size); write(s)
    }.toByteArray()
}
