package dev.vanguard.protocol

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Base64

/** Signing key custody is injected so Android-backed implementations can replace this adapter. */
interface EventSigner {
    val encodedPublicKey: String
    fun sign(message: ByteArray): ByteArray
}

interface EventSignatureVerifier {
    fun verify(encodedPublicKey: String, message: ByteArray, signature: ByteArray): Boolean
}

/** JVM reference implementation for development and tests; not persistent production key custody. */
class JvmEd25519Signer(private val keyPair: KeyPair) : EventSigner {
    override val encodedPublicKey: String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(keyPair.public.encoded)

    override fun sign(message: ByteArray): ByteArray =
        Signature.getInstance("Ed25519").run {
            initSign(keyPair.private)
            update(message)
            sign()
        }

    companion object {
        fun generate(): JvmEd25519Signer =
            JvmEd25519Signer(KeyPairGenerator.getInstance("Ed25519").generateKeyPair())
    }
}

class JvmEd25519Verifier : EventSignatureVerifier {
    override fun verify(
        encodedPublicKey: String,
        message: ByteArray,
        signature: ByteArray
    ): Boolean = try {
        val keyBytes = Base64.getUrlDecoder().decode(encodedPublicKey)
        val publicKey = java.security.KeyFactory.getInstance("Ed25519")
            .generatePublic(java.security.spec.X509EncodedKeySpec(keyBytes))
        Signature.getInstance("Ed25519").run {
            initVerify(publicKey)
            update(message)
            verify(signature)
        }
    } catch (_: Exception) {
        false
    }
}

object Base64Url {
    fun encode(bytes: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    fun decode(value: String): ByteArray = Base64.getUrlDecoder().decode(value)
}
