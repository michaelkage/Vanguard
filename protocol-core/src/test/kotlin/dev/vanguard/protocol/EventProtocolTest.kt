package dev.vanguard.protocol

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class EventProtocolTest {
    private fun protocol(): EventProtocol {
        val signer = JvmEd25519Signer.generate()
        return EventProtocol(signer, JvmEd25519Verifier())
    }

    @Test
    fun `signed event verifies`() {
        val protocol = protocol()
        val event = protocol.create("message.created", 1_800_000_000_000, """{"body":"hello"}""")
        assertTrue(protocol.verify(event))
    }

    @Test
    fun `tampered payload is rejected`() {
        val protocol = protocol()
        val event = protocol.create("message.created", 1_800_000_000_000, """{"body":"hello"}""")
        assertFailsWith<ProtocolException.InvalidEventId> {
            protocol.verify(event.copy(payloadCanonicalJson = """{"body":"changed"}"""))
        }
    }

    @Test
    fun `invalid signature is rejected`() {
        val protocol = protocol()
        val event = protocol.create("message.created", 1_800_000_000_000, """{"body":"hello"}""")
        assertFailsWith<ProtocolException.InvalidSignature> {
            protocol.verify(event.copy(signature = "not-a-valid-signature"))
        }
    }

    @Test
    fun `expired event is rejected when clock is supplied`() {
        val protocol = protocol()
        val event = protocol.create(
            "message.created",
            1_800_000_000_000,
            """{"body":"hello"}""",
            expiresAtEpochMs = 1_800_000_060_000
        )
        assertFailsWith<ProtocolException.ExpiredEvent> {
            protocol.verify(event, nowEpochMs = 1_800_000_060_000)
        }
    }

    @Test
    fun `event store deduplicates by event ID`() {
        val event = protocol().create("message.created", 1_800_000_000_000, """{"body":"hello"}""")
        val store = InMemoryEventStore()
        assertTrue(store.insertIfAbsent(event))
        assertFalse(store.insertIfAbsent(event))
        assertEquals(1, store.all().size)
    }

    @Test
    fun `relay queue deduplicates and acknowledges`() {
        val queue = InMemoryRelayQueue()
        assertTrue(queue.enqueue("evt-1"))
        assertFalse(queue.enqueue("evt-1"))
        assertEquals(listOf("evt-1"), queue.nextBatch(10))
        queue.acknowledge("evt-1")
        assertTrue(queue.nextBatch(10).isEmpty())
    }
}
