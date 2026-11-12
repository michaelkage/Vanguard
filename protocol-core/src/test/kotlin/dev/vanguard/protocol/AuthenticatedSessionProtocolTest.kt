package dev.vanguard.protocol

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class AuthenticatedSessionProtocolTest {
    private class TestIdentity : AuthenticatedSessionProtocol.IdentitySigner {
        private val pair: KeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        override val publicKeySpki: ByteArray = pair.public.encoded

        override fun sign(message: ByteArray): ByteArray =
            Signature.getInstance("Ed25519").run {
                initSign(pair.private)
                update(message)
                sign()
            }
    }

    private class ReplayGuard : AuthenticatedSessionProtocol.ReplayGuard {
        override val retentionMillis = AuthenticatedSessionProtocol.MIN_REPLAY_RETENTION_MILLIS
        private val claimed = mutableSetOf<String>()

        override fun claim(sessionId: ByteArray, initiatorNonce: ByteArray): Boolean =
            claimed.add(
                Base64.getEncoder().encodeToString(sessionId) + ":" +
                    Base64.getEncoder().encodeToString(initiatorNonce)
            )
    }

    private val verifier = AuthenticatedSessionProtocol.IdentityVerifier { publicKey, message, signature ->
        runCatching {
            val key = java.security.KeyFactory.getInstance("Ed25519")
                .generatePublic(java.security.spec.X509EncodedKeySpec(publicKey))
            Signature.getInstance("Ed25519").run {
                initVerify(key)
                update(message)
                verify(signature)
            }
        }.getOrDefault(false)
    }

    private val trusted = AuthenticatedSessionProtocol.AuthorTrustPolicy { true }

    private fun timePolicy(now: () -> Long = { 1_000_000L }) = AuthenticatedSessionProtocol.HandshakeTimePolicy(now)

    private fun establish(): Pair<
        AuthenticatedSessionProtocol.SecurePeerSession,
        AuthenticatedSessionProtocol.SecurePeerSession
    > {
        val initiator = TestIdentity()
        val responder = TestIdentity()
        val pending = AuthenticatedSessionProtocol.begin(initiator, timePolicy())
        val accepted = AuthenticatedSessionProtocol.accept(
            pending.hello,
            responder,
            verifier,
            trusted,
            ReplayGuard(),
                timePolicy()
        )
        val initiatorSession = pending.complete(accepted.response, verifier, trusted)
        return initiatorSession to accepted.session
    }

    @Test
    fun `handshake frames round trip with fixed width framing`() {
        val initiator = TestIdentity()
        val responder = TestIdentity()
        val pending = AuthenticatedSessionProtocol.begin(initiator, timePolicy())
        val helloFrame = AuthenticatedSessionProtocol.encodeHelloFrame(pending.hello)
        val decodedHello = AuthenticatedSessionProtocol.decodeHelloFrame(helloFrame)

        assertContentEquals(pending.hello.sessionId, decodedHello.sessionId)
        assertEquals(pending.hello.createdAtEpochMs, decodedHello.createdAtEpochMs)
        assertContentEquals(pending.hello.initiatorNonce, decodedHello.initiatorNonce)
        assertContentEquals(pending.hello.ephemeralPublicKeySpki, decodedHello.ephemeralPublicKeySpki)
        assertContentEquals(pending.hello.identityPublicKeySpki, decodedHello.identityPublicKeySpki)
        assertContentEquals(pending.hello.signature, decodedHello.signature)

        val accepted = AuthenticatedSessionProtocol.accept(
            decodedHello,
            responder,
            verifier,
            trusted,
            ReplayGuard(),
                timePolicy()
        )
        val responseFrame = AuthenticatedSessionProtocol.encodeResponseFrame(accepted.response)
        val decodedResponse = AuthenticatedSessionProtocol.decodeResponseFrame(responseFrame)
        val session = pending.complete(decodedResponse, verifier, trusted)

        assertContentEquals(
            "codec verified".toByteArray(),
            accepted.session.decrypt(session.encrypt("codec verified".toByteArray()))
        )
        session.close()
        accepted.session.close()
        pending.close()
    }

    @Test
    fun `handshake codec rejects wrong frame type and trailing data`() {
        val pending = AuthenticatedSessionProtocol.begin(TestIdentity(), timePolicy())
        val valid = AuthenticatedSessionProtocol.encodeHelloFrame(pending.hello)

        assertFailsWith<IllegalArgumentException> {
            AuthenticatedSessionProtocol.decodeResponseFrame(valid)
        }
        assertFailsWith<IllegalArgumentException> {
            AuthenticatedSessionProtocol.decodeHelloFrame(valid + byteArrayOf(0))
        }
        assertFailsWith<IllegalArgumentException> {
            AuthenticatedSessionProtocol.decodeHelloFrame(byteArrayOf(0, 0, 0))
        }
        pending.close()
    }

    @Test
    fun `bounded replay guard rejects duplicates and fails closed at capacity`() {
        var now = 0L
        val guard = AuthenticatedSessionProtocol.BoundedInMemoryReplayGuard(
            capacity = 2,
            ttlMillis = 100,
            elapsedClock = { now }
        )
        val firstId = ByteArray(16) { 1 }
        val secondId = ByteArray(16) { 2 }
        val thirdId = ByteArray(16) { 3 }
        val firstNonce = ByteArray(32) { 4 }

        assertTrue(guard.claim(firstId, firstNonce))
        assertFalse(guard.claim(firstId, firstNonce))
        assertTrue(guard.claim(secondId, firstNonce))
        assertFalse(guard.claim(thirdId, firstNonce))

        now = 100
        assertTrue(guard.claim(thirdId, firstNonce))
        assertTrue(guard.claim(firstId, firstNonce))
    }

    @Test
    fun `replay guard rejects invalid identifiers and invalid clock values`() {
        var now = 0L
        val guard = AuthenticatedSessionProtocol.BoundedInMemoryReplayGuard(
            elapsedClock = { now }
        )
        assertFailsWith<IllegalArgumentException> {
            guard.claim(ByteArray(15), ByteArray(32))
        }
        assertFailsWith<IllegalArgumentException> {
            guard.claim(ByteArray(16), ByteArray(31))
        }
        now = -1
        assertFailsWith<IllegalArgumentException> {
            guard.claim(ByteArray(16), ByteArray(32))
        }
    }

    @Test
    fun `HKDF SHA-256 matches RFC 5869 test case one`() {
        fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

        val ikm = ByteArray(22) { 0x0b }
        val salt = hex("000102030405060708090a0b0c")
        val info = hex("f0f1f2f3f4f5f6f7f8f9")
        val actual = AuthenticatedSessionProtocol.hkdfSha256(ikm, salt, info, 42)

        assertContentEquals(
            hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"),
            actual
        )
        assertFailsWith<IllegalArgumentException> {
            AuthenticatedSessionProtocol.hkdfSha256(ikm, salt, info, 0)
        }
        assertFailsWith<IllegalArgumentException> {
            AuthenticatedSessionProtocol.hkdfSha256(ikm, salt, info, 8161)
        }
    }

    @Test
    fun `replay guard fails closed when its monotonic clock moves backwards`() {
        var now = 10L
        val guard = AuthenticatedSessionProtocol.BoundedInMemoryReplayGuard(
            ttlMillis = 100,
            elapsedClock = { now }
        )
        assertTrue(guard.claim(ByteArray(16) { 1 }, ByteArray(32) { 2 }))
        now = 9
        assertFailsWith<IllegalArgumentException> {
            guard.claim(ByteArray(16) { 3 }, ByteArray(32) { 4 })
        }
    }

    @Test
    fun `both peers derive interoperable directional session keys`() {
        val (initiator, responder) = establish()
        try {
            val message = "offline campus message".toByteArray()
            val packet = initiator.encrypt(message)
            assertContentEquals(message, responder.decrypt(packet))

            val reply = "acknowledged".toByteArray()
            assertContentEquals(reply, initiator.decrypt(responder.encrypt(reply)))
        } finally {
            initiator.close()
            responder.close()
        }
    }

    @Test
    fun `replayed packets and out of order packets are rejected`() {
        val (initiator, responder) = establish()
        try {
            val first = initiator.encrypt("first".toByteArray())
            val second = initiator.encrypt("second".toByteArray())

            assertContentEquals("first".toByteArray(), responder.decrypt(first))
            assertFailsWith<IllegalArgumentException> { responder.decrypt(first) }
            assertFailsWith<IllegalArgumentException> { responder.decrypt(second.copyOf().also {
                it[8] = 9
            }) }
            assertContentEquals("second".toByteArray(), responder.decrypt(second))
        } finally {
            initiator.close()
            responder.close()
        }
    }

    @Test
    fun `failed authentication does not consume the receive sequence`() {
        val (initiator, responder) = establish()
        try {
            val valid = initiator.encrypt("authenticated".toByteArray())
            val tampered = valid.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
            assertFailsWith<javax.crypto.AEADBadTagException> { responder.decrypt(tampered) }
            assertContentEquals("authenticated".toByteArray(), responder.decrypt(valid))
        } finally {
            initiator.close()
            responder.close()
        }
    }

    @Test
    fun `hello signature tampering is rejected before replay claim`() {
        val initiator = TestIdentity()
        val responder = TestIdentity()
        val pending = AuthenticatedSessionProtocol.begin(initiator, timePolicy())
        val tampered = pending.hello.copy(signature = pending.hello.signature.copyOf().also {
            it[0] = (it[0].toInt() xor 1).toByte()
        })
        val replayGuard = ReplayGuard()

        assertFailsWith<IllegalArgumentException> {
            AuthenticatedSessionProtocol.accept(
                tampered,
                responder,
                verifier,
                trusted,
                replayGuard,
                timePolicy()
            )
        }
        val accepted = AuthenticatedSessionProtocol.accept(
            pending.hello,
            responder,
            verifier,
            trusted,
            replayGuard,
                timePolicy()
        )
        assertTrue(accepted.response.signature.isNotEmpty())
        accepted.session.close()
        pending.close()
    }

    @Test
    fun `tampered responder transcript signature is rejected`() {
        val initiator = TestIdentity()
        val responder = TestIdentity()
        val pending = AuthenticatedSessionProtocol.begin(initiator, timePolicy())
        val accepted = AuthenticatedSessionProtocol.accept(
            pending.hello,
            responder,
            verifier,
            trusted,
            ReplayGuard(),
                timePolicy()
        )
        val tamperedResponse = accepted.response.copy(
            signature = accepted.response.signature.copyOf().also {
                it[it.lastIndex] = (it.last().toInt() xor 1).toByte()
            }
        )

        assertFailsWith<IllegalArgumentException> {
            pending.complete(tamperedResponse, verifier, trusted)
        }
        accepted.session.close()
    }

    @Test
    fun `untrusted initiator is rejected before replay state is consumed`() {
        val initiator = TestIdentity()
        val responder = TestIdentity()
        val pending = AuthenticatedSessionProtocol.begin(initiator, timePolicy())
        var replayClaims = 0
        val replayGuard = object : AuthenticatedSessionProtocol.ReplayGuard {
            override val retentionMillis = AuthenticatedSessionProtocol.MIN_REPLAY_RETENTION_MILLIS
            override fun claim(sessionId: ByteArray, initiatorNonce: ByteArray): Boolean {
                replayClaims += 1
                return true
            }
        }

        assertFailsWith<IllegalArgumentException> {
            AuthenticatedSessionProtocol.accept(
                pending.hello,
                responder,
                verifier,
                AuthenticatedSessionProtocol.AuthorTrustPolicy { false },
                replayGuard,
                timePolicy()
            )
        }
        assertEquals(0, replayClaims)
        pending.close()
    }

    @Test
    fun `replayed handshake hello is rejected`() {
        val initiator = TestIdentity()
        val responder = TestIdentity()
        val replayGuard = ReplayGuard()
        val pending = AuthenticatedSessionProtocol.begin(initiator, timePolicy())

        val accepted = AuthenticatedSessionProtocol.accept(
            pending.hello,
            responder,
            verifier,
            trusted,
            replayGuard,
                timePolicy()
        )
        assertFailsWith<IllegalArgumentException> {
            AuthenticatedSessionProtocol.accept(
                pending.hello,
                responder,
                verifier,
                trusted,
                replayGuard,
                timePolicy()
            )
        }
        accepted.session.close()
        pending.close()
    }

    @Test
    fun `untrusted responder identity cannot establish an initiator session`() {
        val initiator = TestIdentity()
        val responder = TestIdentity()
        val pending = AuthenticatedSessionProtocol.begin(initiator, timePolicy())
        val accepted = AuthenticatedSessionProtocol.accept(
            pending.hello,
            responder,
            verifier,
            trusted,
            ReplayGuard(),
                timePolicy()
        )

        assertFailsWith<IllegalArgumentException> {
            pending.complete(
                accepted.response,
                verifier,
                AuthenticatedSessionProtocol.AuthorTrustPolicy { false }
            )
        }
        accepted.session.close()
    }

    @Test
    fun `expired hello is rejected before replay state is consumed`() {
        var now = 100_000L
        val pending = AuthenticatedSessionProtocol.begin(TestIdentity(), timePolicy { now })
        var claims = 0
        val guard = object : AuthenticatedSessionProtocol.ReplayGuard {
            override val retentionMillis = AuthenticatedSessionProtocol.MIN_REPLAY_RETENTION_MILLIS
            override fun claim(sessionId: ByteArray, initiatorNonce: ByteArray): Boolean {
                claims += 1
                return true
            }
        }
        now += AuthenticatedSessionProtocol.MAX_HANDSHAKE_AGE_MILLIS + 1
        assertFailsWith<IllegalArgumentException> {
            AuthenticatedSessionProtocol.accept(pending.hello, TestIdentity(), verifier, trusted, guard, timePolicy { now })
        }
        assertEquals(0, claims)
        pending.close()
    }

    @Test
    fun `future hello beyond configured skew is rejected`() {
        var now = 100_000L
        val pending = AuthenticatedSessionProtocol.begin(TestIdentity(), timePolicy { now })
        now -= AuthenticatedSessionProtocol.MAX_FUTURE_SKEW_MILLIS + 1
        assertFailsWith<IllegalArgumentException> {
            AuthenticatedSessionProtocol.accept(pending.hello, TestIdentity(), verifier, trusted, ReplayGuard(), timePolicy { now })
        }
        pending.close()
    }

    @Test
    fun `freshness boundaries are inclusive`() {
        var now = 100_000L
        val future = AuthenticatedSessionProtocol.begin(TestIdentity(), timePolicy { now })
        now -= AuthenticatedSessionProtocol.MAX_FUTURE_SKEW_MILLIS
        val acceptedFuture = AuthenticatedSessionProtocol.accept(future.hello, TestIdentity(), verifier, trusted, ReplayGuard(), timePolicy { now })
        acceptedFuture.session.close()
        future.close()

        now = 100_000L
        val age = AuthenticatedSessionProtocol.begin(TestIdentity(), timePolicy { now })
        now += AuthenticatedSessionProtocol.MAX_HANDSHAKE_AGE_MILLIS
        val acceptedAge = AuthenticatedSessionProtocol.accept(age.hello, TestIdentity(), verifier, trusted, ReplayGuard(), timePolicy { now })
        acceptedAge.session.close()
        age.close()
    }

    @Test
    fun `initiator completion rechecks expiry`() {
        var now = 50_000L
        val pending = AuthenticatedSessionProtocol.begin(TestIdentity(), timePolicy { now })
        val accepted = AuthenticatedSessionProtocol.accept(pending.hello, TestIdentity(), verifier, trusted, ReplayGuard(), timePolicy { now })
        now += AuthenticatedSessionProtocol.MAX_HANDSHAKE_AGE_MILLIS + 1
        assertFailsWith<IllegalArgumentException> { pending.complete(accepted.response, verifier, trusted) }
        accepted.session.close()
    }

    @Test
    fun `handshake clock rollback fails closed`() {
        var now = 10_000L
        val policy = timePolicy { now }
        policy.captureNow()
        now -= 1
        assertFailsWith<IllegalArgumentException> { policy.captureNow() }
    }

    @Test
    fun `creation timestamp tampering invalidates initiator signature`() {
        val pending = AuthenticatedSessionProtocol.begin(TestIdentity(), timePolicy())
        val tampered = pending.hello.copy(createdAtEpochMs = pending.hello.createdAtEpochMs + 1)
        assertFailsWith<IllegalArgumentException> {
            AuthenticatedSessionProtocol.accept(tampered, TestIdentity(), verifier, trusted, ReplayGuard(), timePolicy())
        }
        pending.close()
    }

    @Test
    fun `replay guard with insufficient retention is rejected before claim`() {
        val pending = AuthenticatedSessionProtocol.begin(TestIdentity(), timePolicy())
        var claims = 0
        val shortGuard = object : AuthenticatedSessionProtocol.ReplayGuard {
            override val retentionMillis = AuthenticatedSessionProtocol.MIN_REPLAY_RETENTION_MILLIS - 1
            override fun claim(sessionId: ByteArray, initiatorNonce: ByteArray): Boolean {
                claims += 1
                return true
            }
        }
        assertFailsWith<IllegalArgumentException> {
            AuthenticatedSessionProtocol.accept(pending.hello, TestIdentity(), verifier, trusted, shortGuard, timePolicy())
        }
        assertEquals(0, claims)
        pending.close()
    }

    @Test
    fun `custom freshness window requires matching replay retention`() {
        val policy = AuthenticatedSessionProtocol.HandshakeTimePolicy(
            { 1_000_000L },
            maximumAgeMillis = 240_000L,
            maximumFutureSkewMillis = 45_000L
        )
        val pending = AuthenticatedSessionProtocol.begin(TestIdentity(), policy)
        val guard = object : AuthenticatedSessionProtocol.ReplayGuard {
            override val retentionMillis = policy.minimumReplayRetentionMillis
            override fun claim(sessionId: ByteArray, initiatorNonce: ByteArray): Boolean = true
        }
        val accepted = AuthenticatedSessionProtocol.accept(pending.hello, TestIdentity(), verifier, trusted, guard, policy)
        accepted.session.close()
        pending.close()
    }

    @Test
    fun `default replay guard retention covers default freshness policy`() {
        val guard = AuthenticatedSessionProtocol.BoundedInMemoryReplayGuard()
        val policy = AuthenticatedSessionProtocol.HandshakeTimePolicy({ 1_000L })
        assertTrue(guard.retentionMillis >= policy.minimumReplayRetentionMillis)
    }

    @Test
    fun `closed sessions reject further cryptographic operations`() {
        val (initiator, responder) = establish()
        initiator.close()
        responder.close()

        assertFailsWith<IllegalStateException> { initiator.encrypt(byteArrayOf(1)) }
        assertFailsWith<IllegalStateException> {
            responder.decrypt(ByteArray(AuthenticatedSessionProtocol.MAX_PACKET_BYTES))
        }
    }

    @Test
    fun `session packets respect the Nearby payload ceiling`() {
        val (initiator, responder) = establish()
        try {
            val payload = ByteArray(AuthenticatedSessionProtocol.MAX_PLAINTEXT_BYTES)
            val packet = initiator.encrypt(payload)
            assertTrue(packet.size <= AuthenticatedSessionProtocol.MAX_PACKET_BYTES)
            assertEquals(payload.size, responder.decrypt(packet).size)
            assertFailsWith<IllegalArgumentException> {
                initiator.encrypt(ByteArray(AuthenticatedSessionProtocol.MAX_PLAINTEXT_BYTES + 1))
            }
            assertFailsWith<IllegalArgumentException> {
                responder.decrypt(ByteArray(AuthenticatedSessionProtocol.MAX_PACKET_BYTES + 1))
            }
            assertFailsWith<IllegalArgumentException> {
                responder.decrypt(ByteArray(1 + Long.SIZE_BYTES))
            }
        } finally {
            initiator.close()
            responder.close()
        }
    }
}
