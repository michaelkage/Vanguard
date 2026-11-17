package dev.vanguard.android.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import dev.vanguard.protocol.EventSigner
import java.security.KeyStore
import java.security.Signature
import java.util.Base64

/**
 * Android KeyStore-backed [EventSigner].
 * Requires a generated key pair with the provided [keyAlias] in the Android KeyStore.
 */
class AndroidKeySigner(
    private val keyAlias: String
) : EventSigner {

    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }

    override val encodedPublicKey: String by lazy {
        val publicKey = keyStore.getCertificate(keyAlias)?.publicKey
            ?: throw IllegalStateException("Key alias $keyAlias not found in KeyStore")
        Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.encoded)
    }

    override fun sign(message: ByteArray): ByteArray {
        val entry = keyStore.getEntry(keyAlias, null) as? KeyStore.PrivateKeyEntry
            ?: throw IllegalStateException("Key alias $keyAlias does not contain a private key")

        return Signature.getInstance("SHA256withEd25519").run {
            initSign(entry.privateKey)
            update(message)
            sign()
        }
    }

    companion object {
        /**
         * Ensures a key exists for the given alias. If it does not exist, it is generated.
         */
        fun ensureKeyExists(keyAlias: String) {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply {
                load(null)
            }
            if (!keyStore.containsAlias(keyAlias)) {
                val keyPairGenerator = java.security.KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC,
                    "AndroidKeyStore"
                )
                val parameterSpec = KeyGenParameterSpec.Builder(
                    keyAlias,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
                )
                    .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("ed25519"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .build()
                keyPairGenerator.initialize(parameterSpec)
                keyPairGenerator.generateKeyPair()
            }
        }
    }
}
