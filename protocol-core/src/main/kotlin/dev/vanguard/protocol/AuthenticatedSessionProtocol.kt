package dev.vanguard.protocol

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Platform-neutral reference for Vanguard's authenticated ephemeral peer session.
 *
 * This protocol is intentionally separate from event signing. Ed25519 authenticates
 * the handshake transcript; a fresh X25519 key pair derives per-session traffic keys.
 * Callers must provide a fail-closed author trust policy and a replay guard.
 */
object AuthenticatedSessionProtocol {
    const val VERSION = 1
    const val MAX_PACKET_BYTES = 24 * 1024
    const val MAX_PLAINTEXT_BYTES = MAX_PACKET_BYTES - PACKET_HEADER_BYTES - GCM_TAG_BYTES

    private const val SESSION_ID_BYTES = 16
    private const val NONCE_BYTES = 32
    private const val X25519_PUBLIC_KEY_BYTES = 44
    private const val ED25519_PUBLIC_KEY_BYTES = 44
    private const val ED25519_SIGNATURE_BYTES = 64
    private const val PACKET_HEADER_BYTES = 1 + Long.SIZE_BYTES
    private const val GCM_TAG_BYTES = 16
    private const val TRAFFIC_KEY_BYTES = 32
    private const val NONCE_PREFIX_BYTES = 4
    private const val HKDF_OUTPUT_BYTES = 2 * (TRAFFIC_KEY_BYTES + NONCE_PREFIX_BYTES)
    private const val HELLO_DOMAIN = "VANGUARD_PEER_HELLO_V1"
    private const val RESPONSE_DOMAIN = "VANGUARD_PEER_RESPONSE_V1"
    private const val KEY_DERIVATION_DOMAIN = "VANGUARD_PEER_TRAFFIC_KEYS_V1"
    private const val PACKET_DOMAIN = "VANGUARD_PEER_PACKET_V1"

    private val random = SecureRandom()

    interface IdentitySigner {
        /** Ed25519 X.509 SubjectPublicKeyInfo bytes. */
        val publicKeySpki: ByteArray
        fun sign(message: ByteArray): ByteArray
    }

    fun interface IdentityVerifier {
        fun verify(publicKeySpki: ByteArray, message: ByteArray, signature: ByteArray): Boolean
    }

    fun interface AuthorTrustPolicy {
        /** Must return false for unknown, suspended, revoked, or stale identities. */
        fun isTrusted(publicKeySpki: ByteArray): Boolean
    }

    fun interface ReplayGuard {
        /** Atomically claims a session ID + initiator nonce until the handshake expires. */
        fun claim(sessionId: ByteArray, initiatorNonce: ByteArray): Boolean
    }

    enum class Role { INITIATOR, RESPONDER }

    data class Hello(
        val version: Int,
        val sessionId: ByteArray,
        val initiatorNonce: ByteArray,
        val ephemeralPublicKeySpki: ByteArray,
        val identityPublicKeySpki: ByteArray,
        val signature: ByteArray
    )

    data class Response(
        val version: Int,
        val sessionId: ByteArray,
        val initiatorNonce: ByteArray,
        val responderNonce: ByteArray,
        val ephemeralPublicKeySpki: ByteArray,
        val identityPublicKeySpki: ByteArray,
        val signature: ByteArray
    )

    data class ResponderResult(
        val response: Response,
        val session: SecurePeerSession
    )

    class PendingInitiatorHandshake internal constructor(
        val hello: Hello,
        private val ephemeralPrivateKey: PrivateKey,
        private val localIdentityPublicKey: ByteArray
    ) : AutoCloseable {
        private var completed = false

        @Synchronized
        fun complete(
            response: Response,
            verifier: IdentityVerifier,
            authorTrustPolicy: AuthorTrustPolicy
        ): SecurePeerSession {
            check(!completed) { "Handshake has already been completed or closed" }
            try {
                require(response.version == VERSION) { "Unsupported peer-session version" }
                require(response.sessionId.contentEquals(hello.sessionId)) {
                    "Peer-session response has the wrong session ID"
                }
                require(response.initiatorNonce.contentEquals(hello.initiatorNonce)) {
                    "Peer-session response does not bind the initiator nonce"
                }
                validateNonce(response.responderNonce, "responder nonce")
                require(!response.responderNonce.contentEquals(hello.initiatorNonce)) {
                    "Peer-session nonces must be distinct"
                }
                require(response.signature.size == ED25519_SIGNATURE_BYTES) {
                    "Invalid peer-session response signature length"
                }
                validatePublicKey(response.ephemeralPublicKeySpki, X25519_PUBLIC_KEY_BYTES, "X25519")
                validatePublicKey(response.identityPublicKeySpki, ED25519_PUBLIC_KEY_BYTES, "Ed25519")
                require(!response.identityPublicKeySpki.contentEquals(localIdentityPublicKey)) {
                    "Peer-session identity keys must be distinct"
                }

                val unsignedResponse = responseUnsignedBytes(
                    hello,
                    response.sessionId,
                    response.initiatorNonce,
                    response.responderNonce,
                    response.ephemeralPublicKeySpki,
                    response.identityPublicKeySpki
                )
                require(verifier.verify(
                    response.identityPublicKeySpki.copyOf(),
                    unsignedResponse,
                    response.signature.copyOf()
                )) { "Peer-session responder signature is invalid" }
                require(authorTrustPolicy.isTrusted(response.identityPublicKeySpki.copyOf())) {
                    "Peer-session responder is not trusted"
                }

                val transcript = transcriptHash(hello, response)
                val sharedSecret = agree(ephemeralPrivateKey, response.ephemeralPublicKeySpki)
                try {
                    return deriveSession(sharedSecret, transcript, Role.INITIATOR,
                        response.identityPublicKeySpki.copyOf())
                } finally {
                    sharedSecret.fill(0)
                }
            } finally {
                completed = true
                destroy(ephemeralPrivateKey)
            }
        }

        @Synchronized
        override fun close() {
            if (!completed) {
                completed = true
                destroy(ephemeralPrivateKey)
            }
        }
    }

    fun begin(
        identity: IdentitySigner,
        secureRandom: SecureRandom = random
    ): PendingInitiatorHandshake {
        val identityPublicKey = identity.publicKeySpki.copyOf()
        validatePublicKey(identityPublicKey, ED25519_PUBLIC_KEY_BYTES, "Ed25519")
        val ephemeral = generateX25519(secureRandom)
        val sessionId = ByteArray(SESSION_ID_BYTES).also(secureRandom::nextBytes)
        val nonce = ByteArray(NONCE_BYTES).also(secureRandom::nextBytes)
        try {
            val unsigned = helloUnsignedBytes(sessionId, nonce, ephemeral.public.encoded, identityPublicKey)
            val signature = identity.sign(unsigned)
            require(signature.size == ED25519_SIGNATURE_BYTES) {
                "Identity signer returned an invalid Ed25519 signature"
            }
            return PendingInitiatorHandshake(
                Hello(VERSION, sessionId, nonce, ephemeral.public.encoded, identityPublicKey, signature.copyOf()),
                ephemeral.private,
                identityPublicKey
            )
        } catch (error: Throwable) {
            destroy(ephemeral.private)
            throw error
        }
    }

    fun accept(
        hello: Hello,
        identity: IdentitySigner,
        verifier: IdentityVerifier,
        authorTrustPolicy: AuthorTrustPolicy,
        replayGuard: ReplayGuard,
        secureRandom: SecureRandom = random
    ): ResponderResult {
        validateHello(hello)
        val initiatorUnsigned = helloUnsignedBytes(
            hello.sessionId,
            hello.initiatorNonce,
            hello.ephemeralPublicKeySpki,
            hello.identityPublicKeySpki
        )
        require(verifier.verify(
            hello.identityPublicKeySpki.copyOf(),
            initiatorUnsigned,
            hello.signature.copyOf()
        )) { "Peer-session initiator signature is invalid" }
        require(authorTrustPolicy.isTrusted(hello.identityPublicKeySpki.copyOf())) {
            "Peer-session initiator is not trusted"
        }
        require(replayGuard.claim(hello.sessionId.copyOf(), hello.initiatorNonce.copyOf())) {
            "Peer-session hello was replayed"
        }

        val responderIdentity = identity.publicKeySpki.copyOf()
        validatePublicKey(responderIdentity, ED25519_PUBLIC_KEY_BYTES, "Ed25519")
        require(!responderIdentity.contentEquals(hello.identityPublicKeySpki)) {
            "Peer-session identity keys must be distinct"
        }

        val ephemeral = generateX25519(secureRandom)
        try {
            val responderNonce = ByteArray(NONCE_BYTES).also(secureRandom::nextBytes)
            require(!responderNonce.contentEquals(hello.initiatorNonce)) {
                "Peer-session nonces must be distinct"
            }
            val unsignedResponse = responseUnsignedBytes(
                hello,
                hello.sessionId,
                hello.initiatorNonce,
                responderNonce,
                ephemeral.public.encoded,
                responderIdentity
            )
            val signature = identity.sign(unsignedResponse)
            require(signature.size == ED25519_SIGNATURE_BYTES) {
                "Identity signer returned an invalid Ed25519 signature"
            }
            val response = Response(
                VERSION,
                hello.sessionId.copyOf(),
                hello.initiatorNonce.copyOf(),
                responderNonce,
                ephemeral.public.encoded,
                responderIdentity,
                signature.copyOf()
            )

            val sharedSecret = agree(ephemeral.private, hello.ephemeralPublicKeySpki)
            try {
                val transcript = transcriptHash(hello, response)
                val session = deriveSession(
                    sharedSecret,
                    transcript,
                    Role.RESPONDER,
                    hello.identityPublicKeySpki.copyOf()
                )
                return ResponderResult(response, session)
            } finally {
                sharedSecret.fill(0)
            }
        } finally {
            destroy(ephemeral.private)
        }
    }

    private fun validateHello(hello: Hello) {
        require(hello.version == VERSION) { "Unsupported peer-session version" }
        require(hello.sessionId.size == SESSION_ID_BYTES) { "Invalid peer-session ID" }
        validateNonce(hello.initiatorNonce, "initiator nonce")
        validatePublicKey(hello.ephemeralPublicKeySpki, X25519_PUBLIC_KEY_BYTES, "X25519")
        validatePublicKey(hello.identityPublicKeySpki, ED25519_PUBLIC_KEY_BYTES, "Ed25519")
        require(hello.signature.size == ED25519_SIGNATURE_BYTES) { "Invalid peer-session signature length" }
    }

    private fun validateNonce(value: ByteArray, label: String) {
        require(value.size == NONCE_BYTES) { "Invalid $label" }
    }

    private fun validatePublicKey(value: ByteArray, expectedBytes: Int, algorithm: String) {
        require(value.size == expectedBytes) { "Invalid $algorithm public-key length" }
        KeyFactory.getInstance(algorithm).generatePublic(X509EncodedKeySpec(value))
    }

    private fun generateX25519(secureRandom: SecureRandom): KeyPair =
        KeyPairGenerator.getInstance("X25519").run {
            initialize(java.security.spec.NamedParameterSpec("X25519"), secureRandom)
            generateKeyPair()
        }

    private fun agree(privateKey: PrivateKey, remotePublicKeySpki: ByteArray): ByteArray {
        val remote = KeyFactory.getInstance("X25519")
            .generatePublic(X509EncodedKeySpec(remotePublicKeySpki))
        return KeyAgreement.getInstance("X25519").run {
            init(privateKey)
            doPhase(remote, true)
            generateSecret()
        }.also { secret ->
            require(secret.any { it.toInt() != 0 }) { "Invalid all-zero X25519 shared secret" }
        }
    }

    private fun helloUnsignedBytes(
        sessionId: ByteArray,
        nonce: ByteArray,
        ephemeralPublicKey: ByteArray,
        identityPublicKey: ByteArray
    ): ByteArray = encodeFields(
        HELLO_DOMAIN.toByteArray(Charsets.US_ASCII),
        intBytes(VERSION),
        sessionId,
        nonce,
        ephemeralPublicKey,
        identityPublicKey
    )

    private fun responseUnsignedBytes(
        hello: Hello,
        sessionId: ByteArray,
        initiatorNonce: ByteArray,
        responderNonce: ByteArray,
        ephemeralPublicKey: ByteArray,
        identityPublicKey: ByteArray
    ): ByteArray = encodeFields(
        RESPONSE_DOMAIN.toByteArray(Charsets.US_ASCII),
        encodeHello(hello),
        intBytes(VERSION),
        sessionId,
        initiatorNonce,
        responderNonce,
        ephemeralPublicKey,
        identityPublicKey
    )

    private fun encodeHello(hello: Hello): ByteArray = encodeFields(
        helloUnsignedBytes(
            hello.sessionId,
            hello.initiatorNonce,
            hello.ephemeralPublicKeySpki,
            hello.identityPublicKeySpki
        ),
        hello.signature
    )

    private fun transcriptHash(hello: Hello, response: Response): ByteArray = sha256(
        encodeFields(
            encodeHello(hello),
            responseUnsignedBytes(
                hello,
                response.sessionId,
                response.initiatorNonce,
                response.responderNonce,
                response.ephemeralPublicKeySpki,
                response.identityPublicKeySpki
            ),
            response.signature
        )
    )

    private fun deriveSession(
        sharedSecret: ByteArray,
        transcriptHash: ByteArray,
        role: Role,
        remoteIdentityPublicKey: ByteArray
    ): SecurePeerSession {
        val output = hkdf(
            sharedSecret,
            transcriptHash,
            KEY_DERIVATION_DOMAIN.toByteArray(Charsets.US_ASCII),
            HKDF_OUTPUT_BYTES
        )
        try {
            val initiatorToResponderKey = output.copyOfRange(0, TRAFFIC_KEY_BYTES)
            val initiatorToResponderPrefix = output.copyOfRange(
                TRAFFIC_KEY_BYTES,
                TRAFFIC_KEY_BYTES + NONCE_PREFIX_BYTES
            )
            val responderToInitiatorOffset = TRAFFIC_KEY_BYTES + NONCE_PREFIX_BYTES
            val responderToInitiatorKey = output.copyOfRange(
                responderToInitiatorOffset,
                responderToInitiatorOffset + TRAFFIC_KEY_BYTES
            )
            val responderToInitiatorPrefix = output.copyOfRange(
                responderToInitiatorOffset + TRAFFIC_KEY_BYTES,
                HKDF_OUTPUT_BYTES
            )

            return if (role == Role.INITIATOR) {
                SecurePeerSession(
                    initiatorToResponderKey,
                    initiatorToResponderPrefix,
                    responderToInitiatorKey,
                    responderToInitiatorPrefix,
                    transcriptHash.copyOf(),
                    "i2r",
                    "r2i",
                    remoteIdentityPublicKey
                )
            } else {
                SecurePeerSession(
                    responderToInitiatorKey,
                    responderToInitiatorPrefix,
                    initiatorToResponderKey,
                    initiatorToResponderPrefix,
                    transcriptHash.copyOf(),
                    "r2i",
                    "i2r",
                    remoteIdentityPublicKey
                )
            }
        } finally {
            output.fill(0)
        }
    }

    private fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val extract = Mac.getInstance("HmacSHA256")
        extract.init(SecretKeySpec(salt, "HmacSHA256"))
        val prk = extract.doFinal(ikm)
        try {
            val result = ByteArrayOutputStream()
            var previous = ByteArray(0)
            var counter = 1
            while (result.size() < length) {
                val expand = Mac.getInstance("HmacSHA256")
                expand.init(SecretKeySpec(prk, "HmacSHA256"))
                expand.update(previous)
                expand.update(info)
                expand.update(counter.toByte())
                val next = expand.doFinal()
                previous.fill(0)
                previous = next
                result.write(previous)
                counter += 1
            }
            return result.toByteArray().copyOf(length).also { previous.fill(0) }
        } finally {
            prk.fill(0)
        }
    }

    private fun encodeFields(vararg fields: ByteArray): ByteArray =
        ByteArrayOutputStream().use { output ->
            DataOutputStream(output).use { data ->
                fields.forEach { field ->
                    require(field.size <= MAX_PACKET_BYTES) { "Handshake field exceeds protocol limits" }
                    data.writeInt(field.size)
                    data.write(field)
                }
            }
            output.toByteArray()
        }

    private fun intBytes(value: Int): ByteArray =
        ByteBuffer.allocate(Int.SIZE_BYTES).order(ByteOrder.BIG_ENDIAN).putInt(value).array()

    private fun sha256(value: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value)

    private fun destroy(privateKey: PrivateKey) {
        try {
            (privateKey as? javax.security.auth.Destroyable)?.destroy()
        } catch (_: Exception) {
            // Provider-owned key material is released when its key object is collected.
        }
    }

    private fun baseAad(transcriptHash: ByteArray, direction: String, sequence: Long): ByteArray =
        encodeFields(
            PACKET_DOMAIN.toByteArray(Charsets.US_ASCII),
            transcriptHash,
            direction.toByteArray(Charsets.US_ASCII),
            ByteBuffer.allocate(Long.SIZE_BYTES).putLong(sequence).array()
        )

    class SecurePeerSession internal constructor(
        private val sendKey: ByteArray,
        private val sendNoncePrefix: ByteArray,
        private val receiveKey: ByteArray,
        private val receiveNoncePrefix: ByteArray,
        private val transcriptHash: ByteArray,
        private val sendDirection: String,
        private val receiveDirection: String,
        val remoteIdentityPublicKeySpki: ByteArray
    ) : AutoCloseable {
        private var sendSequence = 0L
        private var receiveSequence = 0L
        private var closed = false

        @Synchronized
        fun encrypt(plaintext: ByteArray): ByteArray {
            checkOpen()
            require(plaintext.size <= MAX_PLAINTEXT_BYTES) { "Peer-session plaintext exceeds packet limit" }
            check(sendSequence < Long.MAX_VALUE) { "Peer-session send sequence exhausted" }
            val sequence = sendSequence
            val nonce = nonce(sendNoncePrefix, sequence)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(sendKey, "AES"), GCMParameterSpec(128, nonce))
            cipher.updateAAD(baseAad(transcriptHash, sendDirection, sequence))
            val ciphertext = cipher.doFinal(plaintext)
            val packet = ByteBuffer.allocate(PACKET_HEADER_BYTES + ciphertext.size)
                .put(VERSION.toByte())
                .putLong(sequence)
                .put(ciphertext)
                .array()
            sendSequence += 1
            return packet
        }

        @Synchronized
        fun decrypt(packet: ByteArray): ByteArray {
            checkOpen()
            require(packet.size in (PACKET_HEADER_BYTES + GCM_TAG_BYTES)..MAX_PACKET_BYTES) {
                "Peer-session packet has an invalid length"
            }
            val buffer = ByteBuffer.wrap(packet)
            val version = buffer.get().toInt() and 0xff
            require(version == VERSION) { "Unsupported peer-session packet version" }
            val sequence = buffer.long
            require(sequence == receiveSequence) { "Peer-session packet is replayed or out of order" }
            val ciphertext = ByteArray(buffer.remaining()).also(buffer::get)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(receiveKey, "AES"),
                GCMParameterSpec(128, nonce(receiveNoncePrefix, sequence))
            )
            cipher.updateAAD(baseAad(transcriptHash, receiveDirection, sequence))
            val plaintext = cipher.doFinal(ciphertext)
            require(plaintext.size <= MAX_PLAINTEXT_BYTES) { "Peer-session plaintext exceeds packet limit" }
            receiveSequence += 1
            return plaintext
        }

        @Synchronized
        override fun close() {
            if (closed) return
            closed = true
            sendKey.fill(0)
            sendNoncePrefix.fill(0)
            receiveKey.fill(0)
            receiveNoncePrefix.fill(0)
            transcriptHash.fill(0)
            remoteIdentityKey.fill(0)
        }

        private fun checkOpen() {
            check(!closed) { "Peer session is closed" }
        }

        private fun nonce(prefix: ByteArray, sequence: Long): ByteArray =
            ByteBuffer.allocate(12).put(prefix).putLong(sequence).array()
    }
}
