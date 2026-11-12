package dev.vanguard.protocol

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
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

    private fun establish(): Pair<
        AuthenticatedSessionProtocol.SecurePeerSession,
        AuthenticatedSessionProtocol.SecurePeerSession
    > {
        val initiator = TestIdentity()
        val responder = TestIdentity()
        val pending = AuthenticatedSessionProtocol.begin(initiator)
        val accepted = AuthenticatedSessionProtocol.accept(
            pending.hello,
            responder,
            verifier,
            trusted,
            ReplayGuard()
        )
        val initiatorSession = pending.complete(accepted.response, verifier, trusted)
        return initiatorSession to accepted.session
    }

    @Test
    fun `handshake frames round trip with fixed width framing`() {
        val initiator = TestIdentity()
        val responder = TestIdentity()
        val pending = AuthenticatedSessionProtocol.begin(initiator)
        val helloFrame = AuthenticatedSessionProtocol.encodeHelloFrame(pending.hello)
        val decodedHello = AuthenticatedSessionProtocol.decodeHelloFrame(helloFrame)

        assertContentEquals(pending.hello.sessionId, decodedHello.sessionId)
        assertContentEquals(pending.hello.initiatorNonce, decodedHello.initiatorNonce)
        assertContentEquals(pending.hello.ephemeralPublicKeySpki, decodedHello.ephemeralPublicKeySpki)
        assertContentEquals(pending.hello.identityPublicKeySpki, decodedHello.identityPublicKeySpki)
        assertContentEquals(pending.hello.signature, decodedHello.signature)

        val accepted = AuthenticatedSessionProtocol.accept(
            decodedHello,
            responder,
            verifier,
            trusted,
            ReplayGuard()
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
        val pending = AuthenticatedSessionProtocol.begin(TestIdentity())
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
        val pending = AuthenticatedSessionProtocol.begin(initiator)
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
                replayGuard
            )
        }
        assertTrue(
            AuthenticatedSessionProtocol.accept(
                pending.hello,
                responder,
                verifier,
                trusted,
                replayGuard
            ).response.signature.isNotEmpty()
        )
        pending.close()
    }

    @Test
    fun `replayed handshake hello is rejected`() {
        val initiator = TestIdentity()
        val responder = TestIdentity()
        val replayGuard = ReplayGuard()
        val pending = AuthenticatedSessionProtocol.begin(initiator)

        val accepted = AuthenticatedSessionProtocol.accept(
            pending.hello,
            responder,
            verifier,
            trusted,
            replayGuard
        )
        assertFailsWith<IllegalArgumentException> {
            AuthenticatedSessionProtocol.accept(
                pending.hello,
                responder,
                verifier,
                trusted,
                replayGuard
            )
        }
        accepted.session.close()
        pending.close()
    }

    @Test
    fun `untrusted responder identity cannot establish an initiator session`() {
        val initiator = TestIdentity()
        val responder = TestIdentity()
        val pending = AuthenticatedSessionProtocol.begin(initiator)
        val accepted = AuthenticatedSessionProtocol.accept(
            pending.hello,
            responder,
            verifier,
            trusted,
            ReplayGuard()
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
        } finally {
            initiator.close()
            responder.close()
        }
    }
}
