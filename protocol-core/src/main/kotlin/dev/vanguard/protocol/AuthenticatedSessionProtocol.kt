package dev.vanguard.protocol

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Provider
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
    const val VERSION = 2
    const val MAX_PACKET_BYTES = 24 * 1024

    private const val SESSION_ID_BYTES = 16
    private const val NONCE_BYTES = 32
    private const val HELLO_FRAME_BYTES = 217
    private const val RESPONSE_FRAME_BYTES = 241
    const val MAX_HANDSHAKE_AGE_MILLIS = 120_000L
    const val MAX_FUTURE_SKEW_MILLIS = 30_000L
    const val REPLAY_RETENTION_MARGIN_MILLIS = 1_000L
    const val MIN_REPLAY_RETENTION_MILLIS = MAX_HANDSHAKE_AGE_MILLIS + MAX_FUTURE_SKEW_MILLIS + REPLAY_RETENTION_MARGIN_MILLIS
    private const val X25519_PUBLIC_KEY_BYTES = 44
    private const val ED25519_PUBLIC_KEY_BYTES = 44
    private const val ED25519_SIGNATURE_BYTES = 64
    private const val PACKET_HEADER_BYTES = 1 + Long.SIZE_BYTES
    private const val GCM_TAG_BYTES = 16
    const val MAX_PLAINTEXT_BYTES = MAX_PACKET_BYTES - PACKET_HEADER_BYTES - GCM_TAG_BYTES
    private const val TRAFFIC_KEY_BYTES = 32
    private const val NONCE_PREFIX_BYTES = 4
    private const val HKDF_OUTPUT_BYTES = 2 * (TRAFFIC_KEY_BYTES + NONCE_PREFIX_BYTES)
    private const val HELLO_DOMAIN = "VANGUARD_PEER_HELLO_V2"
    private const val RESPONSE_DOMAIN = "VANGUARD_PEER_RESPONSE_V2"
    private const val KEY_DERIVATION_DOMAIN = "VANGUARD_PEER_TRAFFIC_KEYS_V2"
    private const val PACKET_DOMAIN = "VANGUARD_PEER_PACKET_V2"
    private val HANDSHAKE_MAGIC = byteArrayOf(0x56, 0x47, 0x48, 0x32)

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

    interface ReplayGuard {
        /**
         * Minimum duration for which a successful claim is guaranteed to remain present.
         * Implementations must report their real retention and must not overstate it.
         */
        val retentionMillis: Long

        /** Atomically claims a session ID + initiator nonce until the handshake expires. */
        fun claim(sessionId: ByteArray, initiatorNonce: ByteArray): Boolean
    }


    /**
     * Caller-owned epoch clock for signed handshake freshness. No system-clock default
     * is provided: production callers must supply their rollback-aware time source.
     */
    class HandshakeTimePolicy(
        private val epochMillis: () -> Long,
        val maximumAgeMillis: Long = MAX_HANDSHAKE_AGE_MILLIS,
        val maximumFutureSkewMillis: Long = MAX_FUTURE_SKEW_MILLIS
    ) {
        private var lastObservedEpochMillis: Long? = null
        init {
            require(maximumAgeMillis in 1..600_000L) { "Invalid maximum handshake age" }
            require(maximumFutureSkewMillis in 0..120_000L) { "Invalid maximum future skew" }
        }
        val minimumReplayRetentionMillis: Long
            get() = maximumAgeMillis + maximumFutureSkewMillis + REPLAY_RETENTION_MARGIN_MILLIS

        @Synchronized fun captureNow(): Long {
            val now = epochMillis()
            require(now >= 0) { "Handshake clock must be non-negative" }
            val previous = lastObservedEpochMillis
            require(previous == null || now >= previous) { "Handshake clock moved backwards" }
            lastObservedEpochMillis = now
            return now
        }
        @Synchronized fun validateCreatedAt(createdAtEpochMs: Long) {
            require(createdAtEpochMs >= 0) { "Handshake creation time must be non-negative" }
            val now = captureNow()
            if (createdAtEpochMs > now) {
                require(createdAtEpochMs - now <= maximumFutureSkewMillis) { "Peer-session hello is too far in the future" }
            } else {
                require(now - createdAtEpochMs <= maximumAgeMillis) { "Peer-session hello has expired" }
            }
        }
    }

    enum class Role { INITIATOR, RESPONDER }

    /**
     * Process-local replay protection. It deliberately fails closed when full.
     * The default clock is monotonic and entries are not persisted across process death.
     */
    class BoundedInMemoryReplayGuard(
        private val capacity: Int = 4096,
        private val ttlMillis: Long = MIN_REPLAY_RETENTION_MILLIS,
        elapsedClock: (() -> Long)? = null
    ) : ReplayGuard {
        private val originNanos = System.nanoTime()
        private val nowElapsedMillis: () -> Long = elapsedClock
            ?: { (System.nanoTime() - originNanos) / 1_000_000L }
        override val retentionMillis: Long
            get() = ttlMillis

        private val entries = LinkedHashMap<String, Long>()
        private var lastObservedElapsedMillis: Long? = null

        init {
            require(capacity in 1..100_000) { "Replay-guard capacity must be between 1 and 100000" }
            require(ttlMillis in 1..86_400_000) { "Replay-guard TTL must be between 1 ms and 24 hours" }
        }

        @Synchronized
        override fun claim(sessionId: ByteArray, initiatorNonce: ByteArray): Boolean {
            require(sessionId.size == SESSION_ID_BYTES) { "Invalid replay-guard session ID" }
            validateNonce(initiatorNonce, "initiator nonce")
            val now = nowElapsedMillis()
            require(now >= 0) { "Replay-guard clock must be monotonic and non-negative" }
            val previousNow = lastObservedElapsedMillis
            require(previousNow == null || now >= previousNow) {
                "Replay-guard clock moved backwards"
            }
            lastObservedElapsedMillis = now

            val iterator = entries.entries.iterator()
            while (iterator.hasNext()) {
                if (iterator.next().value <= now) iterator.remove()
            }

            val key = encodeHex(sessionId) + "." + encodeHex(initiatorNonce)
            if (entries.containsKey(key)) return false
            if (entries.size >= capacity) return false

            val expiresAt = if (Long.MAX_VALUE - now < ttlMillis) Long.MAX_VALUE else now + ttlMillis
            entries[key] = expiresAt
            return true
        }
    }

    /** Fixed-width, versioned binary framing for the two handshake messages. */
    fun encodeHelloFrame(candidate: Hello, cryptoProvider: Provider? = null): ByteArray {
        val hello = copyHello(candidate)
        validateHello(hello, cryptoProvider)
        return ByteArrayOutputStream().use { output ->
            DataOutputStream(output).use { data ->
                data.write(HANDSHAKE_MAGIC)
                data.writeByte(1)
                data.writeInt(hello.version)
                data.writeLong(hello.createdAtEpochMs)
                data.write(hello.sessionId)
                data.write(hello.initiatorNonce)
                data.write(hello.ephemeralPublicKeySpki)
                data.write(hello.identityPublicKeySpki)
                data.write(hello.signature)
            }
            output.toByteArray()
        }.also { require(it.size <= MAX_PACKET_BYTES) { "Handshake frame exceeds packet limit" } }
    }

    fun decodeHelloFrame(frame: ByteArray, cryptoProvider: Provider? = null): Hello {
        val input = openHandshakeFrame(frame, 1)
        val version = input.readInt()
        val createdAtEpochMs = input.readLong()
        val hello = Hello(
            version,
            createdAtEpochMs,
            readExact(input, SESSION_ID_BYTES),
            readExact(input, NONCE_BYTES),
            readExact(input, X25519_PUBLIC_KEY_BYTES),
            readExact(input, ED25519_PUBLIC_KEY_BYTES),
            readExact(input, ED25519_SIGNATURE_BYTES)
        )
        require(input.available() == 0) { "Handshake hello contains trailing bytes" }
        validateHello(hello, cryptoProvider)
        return hello
    }

    fun encodeResponseFrame(candidate: Response, cryptoProvider: Provider? = null): ByteArray {
        val response = copyResponse(candidate)
        validateResponseShape(response, cryptoProvider)
        return ByteArrayOutputStream().use { output ->
            DataOutputStream(output).use { data ->
                data.write(HANDSHAKE_MAGIC)
                data.writeByte(2)
                data.writeInt(response.version)
                data.write(response.sessionId)
                data.write(response.initiatorNonce)
                data.write(response.responderNonce)
                data.write(response.ephemeralPublicKeySpki)
                data.write(response.identityPublicKeySpki)
                data.write(response.signature)
            }
            output.toByteArray()
        }.also { require(it.size <= MAX_PACKET_BYTES) { "Handshake frame exceeds packet limit" } }
    }

    fun decodeResponseFrame(frame: ByteArray, cryptoProvider: Provider? = null): Response {
        val input = openHandshakeFrame(frame, 2)
        val response = Response(
            input.readInt(),
            readExact(input, SESSION_ID_BYTES),
            readExact(input, NONCE_BYTES),
            readExact(input, NONCE_BYTES),
            readExact(input, X25519_PUBLIC_KEY_BYTES),
            readExact(input, ED25519_PUBLIC_KEY_BYTES),
            readExact(input, ED25519_SIGNATURE_BYTES)
        )
        require(input.available() == 0) { "Handshake response contains trailing bytes" }
        validateResponseShape(response, cryptoProvider)
        return response
    }

    private fun openHandshakeFrame(frame: ByteArray, expectedType: Int): DataInputStream {
        val expectedBytes = if (expectedType == 1) HELLO_FRAME_BYTES else RESPONSE_FRAME_BYTES
        require(frame.size == expectedBytes) { "Handshake frame has an invalid length" }
        val input = DataInputStream(ByteArrayInputStream(frame))
        val magic = readExact(input, HANDSHAKE_MAGIC.size)
        require(magic.contentEquals(HANDSHAKE_MAGIC)) { "Unrecognized Vanguard handshake frame" }
        require(input.readUnsignedByte() == expectedType) { "Unexpected Vanguard handshake frame type" }
        return input
    }

    private fun readExact(input: DataInputStream, length: Int): ByteArray =
        ByteArray(length).also(input::readFully)

    private fun validateResponseShape(response: Response, cryptoProvider: Provider? = null) {
        require(response.version == VERSION) { "Unsupported peer-session version" }
        require(response.sessionId.size == SESSION_ID_BYTES) { "Invalid peer-session ID" }
        validateNonce(response.initiatorNonce, "initiator nonce")
        validateNonce(response.responderNonce, "responder nonce")
        require(!response.responderNonce.contentEquals(response.initiatorNonce)) {
            "Peer-session nonces must be distinct"
        }
        validatePublicKey(response.ephemeralPublicKeySpki, X25519_PUBLIC_KEY_BYTES, "X25519", cryptoProvider)
        validatePublicKey(response.identityPublicKeySpki, ED25519_PUBLIC_KEY_BYTES, "Ed25519", cryptoProvider)
        require(response.signature.size == ED25519_SIGNATURE_BYTES) {
            "Invalid peer-session response signature length"
        }
    }

    data class Hello(
        val version: Int,
        val createdAtEpochMs: Long,
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

    private fun copyHello(value: Hello): Hello = value.copy(
        sessionId = value.sessionId.copyOf(),
        initiatorNonce = value.initiatorNonce.copyOf(),
        ephemeralPublicKeySpki = value.ephemeralPublicKeySpki.copyOf(),
        identityPublicKeySpki = value.identityPublicKeySpki.copyOf(),
        signature = value.signature.copyOf()
    )

    private fun copyResponse(value: Response): Response = value.copy(
        sessionId = value.sessionId.copyOf(),
        initiatorNonce = value.initiatorNonce.copyOf(),
        responderNonce = value.responderNonce.copyOf(),
        ephemeralPublicKeySpki = value.ephemeralPublicKeySpki.copyOf(),
        identityPublicKeySpki = value.identityPublicKeySpki.copyOf(),
        signature = value.signature.copyOf()
    )


    class PendingInitiatorHandshake internal constructor(
        hello: Hello,
        private val ephemeralPrivateKey: PrivateKey,
        localIdentityPublicKey: ByteArray,
        private val timePolicy: HandshakeTimePolicy,
        private val cryptoProvider: Provider?
    ) : AutoCloseable {
        private val helloSnapshot = copyHello(hello)
        private val localIdentityKey = localIdentityPublicKey.copyOf()
        val hello: Hello
            get() = copyHello(helloSnapshot)
        private var completed = false

        @Synchronized
        fun complete(
            candidateResponse: Response,
            verifier: IdentityVerifier,
            authorTrustPolicy: AuthorTrustPolicy
        ): SecurePeerSession {
            check(!completed) { "Handshake has already been completed or closed" }
            val hello = helloSnapshot
            val response = copyResponse(candidateResponse)
            try {
                timePolicy.validateCreatedAt(hello.createdAtEpochMs)
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
                validatePublicKey(response.ephemeralPublicKeySpki, X25519_PUBLIC_KEY_BYTES, "X25519", cryptoProvider)
                validatePublicKey(response.identityPublicKeySpki, ED25519_PUBLIC_KEY_BYTES, "Ed25519", cryptoProvider)
                require(!response.identityPublicKeySpki.contentEquals(localIdentityKey)) {
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

                timePolicy.validateCreatedAt(hello.createdAtEpochMs)
                val transcript = transcriptHash(hello, response)
                val sharedSecret = agree(ephemeralPrivateKey, response.ephemeralPublicKeySpki, cryptoProvider)
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
        timePolicy: HandshakeTimePolicy,
        secureRandom: SecureRandom = random,
        cryptoProvider: Provider? = null
    ): PendingInitiatorHandshake {
        val createdAtEpochMs = timePolicy.captureNow()
        val identityPublicKey = identity.publicKeySpki.copyOf()
        validatePublicKey(identityPublicKey, ED25519_PUBLIC_KEY_BYTES, "Ed25519", cryptoProvider)
        val ephemeral = generateX25519(secureRandom, cryptoProvider)
        val sessionId = ByteArray(SESSION_ID_BYTES).also(secureRandom::nextBytes)
        val nonce = ByteArray(NONCE_BYTES).also(secureRandom::nextBytes)
        try {
            val unsigned = helloUnsignedBytes(createdAtEpochMs, sessionId, nonce, ephemeral.public.encoded, identityPublicKey)
            val signature = identity.sign(unsigned)
            require(signature.size == ED25519_SIGNATURE_BYTES) {
                "Identity signer returned an invalid Ed25519 signature"
            }
            return PendingInitiatorHandshake(
                Hello(VERSION, createdAtEpochMs, sessionId, nonce, ephemeral.public.encoded, identityPublicKey, signature.copyOf()),
                ephemeral.private,
                identityPublicKey,
                timePolicy,
                cryptoProvider
            )
        } catch (error: Throwable) {
            destroy(ephemeral.private)
            throw error
        }
    }

    fun accept(
        candidateHello: Hello,
        identity: IdentitySigner,
        verifier: IdentityVerifier,
        authorTrustPolicy: AuthorTrustPolicy,
        replayGuard: ReplayGuard,
        timePolicy: HandshakeTimePolicy,
        secureRandom: SecureRandom = random,
        cryptoProvider: Provider? = null
    ): ResponderResult {
        val hello = copyHello(candidateHello)
        validateHello(hello, cryptoProvider)
        timePolicy.validateCreatedAt(hello.createdAtEpochMs)
        val initiatorUnsigned = helloUnsignedBytes(
            hello.createdAtEpochMs,
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
        timePolicy.validateCreatedAt(hello.createdAtEpochMs)
        require(replayGuard.retentionMillis >= timePolicy.minimumReplayRetentionMillis) {
            "Replay guard retention (" + replayGuard.retentionMillis + " ms) is shorter than the required " +
                timePolicy.minimumReplayRetentionMillis + " ms"
        }
        require(replayGuard.claim(hello.sessionId.copyOf(), hello.initiatorNonce.copyOf())) {
            "Peer-session hello was replayed"
        }

        val responderIdentity = identity.publicKeySpki.copyOf()
        validatePublicKey(responderIdentity, ED25519_PUBLIC_KEY_BYTES, "Ed25519", cryptoProvider)
        require(!responderIdentity.contentEquals(hello.identityPublicKeySpki)) {
            "Peer-session identity keys must be distinct"
        }

        val ephemeral = generateX25519(secureRandom, cryptoProvider)
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

            val sharedSecret = agree(ephemeral.private, hello.ephemeralPublicKeySpki, cryptoProvider)
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

    private fun validateHello(hello: Hello, cryptoProvider: Provider? = null) {
        require(hello.version == VERSION) { "Unsupported peer-session version" }
        require(hello.createdAtEpochMs >= 0) { "Invalid handshake creation time" }
        require(hello.sessionId.size == SESSION_ID_BYTES) { "Invalid peer-session ID" }
        validateNonce(hello.initiatorNonce, "initiator nonce")
        validatePublicKey(hello.ephemeralPublicKeySpki, X25519_PUBLIC_KEY_BYTES, "X25519", cryptoProvider)
        validatePublicKey(hello.identityPublicKeySpki, ED25519_PUBLIC_KEY_BYTES, "Ed25519", cryptoProvider)
        require(hello.signature.size == ED25519_SIGNATURE_BYTES) { "Invalid peer-session signature length" }
    }

    private fun validateNonce(value: ByteArray, label: String) {
        require(value.size == NONCE_BYTES) { "Invalid $label" }
    }

    private fun validatePublicKey(
        value: ByteArray,
        expectedBytes: Int,
        algorithm: String,
        provider: Provider? = null
    ) {
        require(value.size == expectedBytes) { "Invalid $algorithm public-key length" }
        val factory = if (provider == null) KeyFactory.getInstance(algorithm)
            else KeyFactory.getInstance(algorithm, provider)
        factory.generatePublic(X509EncodedKeySpec(value))
    }

    private fun generateX25519(secureRandom: SecureRandom, provider: Provider?): KeyPair {
        val generator = if (provider == null) KeyPairGenerator.getInstance("X25519")
            else KeyPairGenerator.getInstance("X25519", provider)
        if (provider == null) {
            // Resolve reflectively: NamedParameterSpec is absent on older Android releases.
            val parameterType = Class.forName("java.security.spec.NamedParameterSpec")
            val parameterSpec = parameterType
                .getConstructor(String::class.java)
                .newInstance("X25519") as java.security.spec.AlgorithmParameterSpec
            generator.initialize(parameterSpec, secureRandom)
        } else {
            // Bouncy Castle's X25519 generator is parameterized by its algorithm name;
            // avoiding NamedParameterSpec keeps this path compatible with API 23.
            generator.initialize(255, secureRandom)
        }
        return generator.generateKeyPair()
    }

    private fun agree(
        privateKey: PrivateKey,
        remotePublicKeySpki: ByteArray,
        provider: Provider?
    ): ByteArray {
        val factory = if (provider == null) KeyFactory.getInstance("X25519")
            else KeyFactory.getInstance("X25519", provider)
        val remote = factory.generatePublic(X509EncodedKeySpec(remotePublicKeySpki))
        val agreement = if (provider == null) KeyAgreement.getInstance("X25519")
            else KeyAgreement.getInstance("X25519", provider)
        return agreement.run {
            init(privateKey)
            doPhase(remote, true)
            generateSecret()
        }.also { secret ->
            if (secret.none { it.toInt() != 0 }) {
                secret.fill(0)
                throw IllegalArgumentException("Invalid all-zero X25519 shared secret")
            }
        }
    }

    private fun helloUnsignedBytes(
        createdAtEpochMs: Long,
        sessionId: ByteArray,
        nonce: ByteArray,
        ephemeralPublicKey: ByteArray,
        identityPublicKey: ByteArray
    ): ByteArray = encodeFields(
        HELLO_DOMAIN.toByteArray(Charsets.US_ASCII),
        intBytes(VERSION),
        longBytes(createdAtEpochMs),
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
            hello.createdAtEpochMs,
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
        val output = hkdfSha256(
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

    internal fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length in 1..(255 * 32)) { "HKDF-SHA-256 output length must be between 1 and 8160 bytes" }

        val effectiveSalt = if (salt.isEmpty()) ByteArray(32) else salt
        val extract = Mac.getInstance("HmacSHA256")
        val prk = try {
            extract.init(SecretKeySpec(effectiveSalt, "HmacSHA256"))
            extract.doFinal(ikm)
        } finally {
            if (effectiveSalt !== salt) effectiveSalt.fill(0)
        }

        val output = ByteArray(length)
        var previous = ByteArray(0)
        var written = 0
        var counter = 1
        var completed = false
        try {
            while (written < length) {
                val expand = Mac.getInstance("HmacSHA256")
                expand.init(SecretKeySpec(prk, "HmacSHA256"))
                expand.update(previous)
                expand.update(info)
                expand.update(counter.toByte())
                val next = expand.doFinal()
                previous.fill(0)
                previous = next

                val copyLength = minOf(previous.size, length - written)
                previous.copyInto(output, written, 0, copyLength)
                written += copyLength
                counter += 1
            }
            completed = true
            return output
        } finally {
            prk.fill(0)
            previous.fill(0)
            if (!completed) output.fill(0)
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

    private fun encodeHex(bytes: ByteArray): String {
        val alphabet = "0123456789abcdef"
        val output = CharArray(bytes.size * 2)
        bytes.forEachIndexed { index, byte ->
            val value = byte.toInt() and 0xff
            output[index * 2] = alphabet[value ushr 4]
            output[index * 2 + 1] = alphabet[value and 0x0f]
        }
        return String(output)
    }

    private fun longBytes(value: Long): ByteArray = ByteBuffer.allocate(Long.SIZE_BYTES).putLong(value).array()

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
        private val remoteIdentityKey: ByteArray
    ) : AutoCloseable {
        val remoteIdentityPublicKeySpki: ByteArray
            get() = remoteIdentityKey.copyOf()

        private var sendSequence = 0L
        private var receiveSequence = 0L
        private var closed = false

        @Synchronized
        fun encrypt(plaintext: ByteArray): ByteArray {
            checkOpen()
            require(plaintext.size <= MAX_PLAINTEXT_BYTES) { "Peer-session plaintext exceeds packet limit" }
            check(sendSequence < Long.MAX_VALUE) { "Peer-session send sequence exhausted" }
            val sequence = sendSequence
            val plaintextSnapshot = plaintext.copyOf()
            val packetNonce = nonce(sendNoncePrefix, sequence)
            val aad = baseAad(transcriptHash, sendDirection, sequence)
            var ciphertext: ByteArray? = null
            try {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(sendKey, "AES"), GCMParameterSpec(128, packetNonce))
                cipher.updateAAD(aad)
                ciphertext = cipher.doFinal(plaintextSnapshot)
                val packet = ByteBuffer.allocate(PACKET_HEADER_BYTES + ciphertext.size)
                    .put(VERSION.toByte())
                    .putLong(sequence)
                    .put(ciphertext)
                    .array()
                sendSequence += 1
                return packet
            } finally {
                plaintextSnapshot.fill(0)
                packetNonce.fill(0)
                aad.fill(0)
                ciphertext?.fill(0)
            }
        }

        @Synchronized
        fun decrypt(packet: ByteArray): ByteArray {
            checkOpen()
            require(packet.size in (PACKET_HEADER_BYTES + GCM_TAG_BYTES)..MAX_PACKET_BYTES) {
                "Peer-session packet has an invalid length"
            }
            val frame = packet.copyOf()
            var ciphertext: ByteArray? = null
            var packetNonce: ByteArray? = null
            var aad: ByteArray? = null
            try {
                require(frame.size in (PACKET_HEADER_BYTES + GCM_TAG_BYTES)..MAX_PACKET_BYTES) {
                    "Peer-session packet has an invalid length"
                }
                val buffer = ByteBuffer.wrap(frame)
                val version = buffer.get().toInt() and 0xff
                require(version == VERSION) { "Unsupported peer-session packet version" }
                val sequence = buffer.long
                require(sequence == receiveSequence) { "Peer-session packet is replayed or out of order" }
                ciphertext = ByteArray(buffer.remaining()).also(buffer::get)
                packetNonce = nonce(receiveNoncePrefix, sequence)
                aad = baseAad(transcriptHash, receiveDirection, sequence)
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(
                    Cipher.DECRYPT_MODE,
                    SecretKeySpec(receiveKey, "AES"),
                    GCMParameterSpec(128, packetNonce)
                )
                cipher.updateAAD(aad)
                val plaintext = cipher.doFinal(ciphertext)
                require(plaintext.size <= MAX_PLAINTEXT_BYTES) {
                    "Peer-session plaintext exceeds packet limit"
                }
                receiveSequence += 1
                return plaintext
            } finally {
                frame.fill(0)
                ciphertext?.fill(0)
                packetNonce?.fill(0)
                aad?.fill(0)
            }
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
