package fi.digilompakko.wallet

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * A P-256 (ES256) signing key held in the **Android Keystore**, preferring **StrongBox** (the
 * hardware security module) — the Android WSCD. The private key is non-exportable; we only ask the
 * keystore to sign. Falls back to TEE-backed keystore when StrongBox is unavailable.
 */
object SecureKeyStore {
    private const val ALIAS = "fi.digilompakko.wallet.holderkey"
    private const val PROVIDER = "AndroidKeyStore"

    var isStrongBoxBacked = false
        private set

    fun ensureKey() {
        val ks = KeyStore.getInstance(PROVIDER).apply { load(null) }
        if (ks.containsAlias(ALIAS)) {
            isStrongBoxBacked = queryStrongBox()
            return
        }
        try {
            generate(strongBox = true)
            isStrongBoxBacked = true
        } catch (_: StrongBoxUnavailableException) {
            generate(strongBox = false)
            isStrongBoxBacked = queryStrongBox()
        }
    }

    /** Holder public key as a JWK. */
    fun publicJWK(): JWK {
        val pub = certificate().publicKey as ECPublicKey
        val x = pub.w.affineX.to32Bytes()
        val y = pub.w.affineY.to32Bytes()
        return JWK("EC", "P-256", b64url(x), b64url(y))
    }

    /** Sign with ES256; returns a raw r||s (64-byte) JOSE signature. */
    fun sign(data: ByteArray): ByteArray {
        val sig = Signature.getInstance("SHA256withECDSA").apply { initSign(privateKey()) }
        sig.update(data)
        return derToJose(sig.sign(), 32)
    }

    // MARK: - internals

    private fun generate(strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(false)
            .apply { if (strongBox) setIsStrongBoxBacked(true) }
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER).run {
            initialize(spec)
            generateKeyPair()
        }
    }

    private fun privateKey(): PrivateKey {
        val ks = KeyStore.getInstance(PROVIDER).apply { load(null) }
        return (ks.getEntry(ALIAS, null) as KeyStore.PrivateKeyEntry).privateKey
    }

    private fun certificate() =
        KeyStore.getInstance(PROVIDER).apply { load(null) }.getCertificate(ALIAS)

    private fun queryStrongBox(): Boolean = try {
        val key = privateKey()
        val factory = KeyFactory.getInstance(key.algorithm, PROVIDER)
        val info = factory.getKeySpec(key, KeyInfo::class.java)
        @Suppress("DEPRECATION")
        info.isInsideSecureHardware
    } catch (_: Exception) { false }
}

/** Left-pad/trim a BigInteger to exactly 32 bytes (drops the sign byte if present). */
fun BigInteger.to32Bytes(): ByteArray {
    val raw = toByteArray()
    val out = ByteArray(32)
    when {
        raw.size == 32 -> return raw
        raw.size == 33 && raw[0].toInt() == 0 -> System.arraycopy(raw, 1, out, 0, 32)
        raw.size < 32 -> System.arraycopy(raw, 0, out, 32 - raw.size, raw.size)
        else -> System.arraycopy(raw, raw.size - 32, out, 0, 32)
    }
    return out
}
