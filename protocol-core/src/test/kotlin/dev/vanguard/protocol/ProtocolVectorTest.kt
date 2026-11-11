package dev.vanguard.protocol

import java.nio.charset.StandardCharsets
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ProtocolVectorTest {
    @Test
    fun `shared v1 message vector matches canonical encoder and event ID`() {
        val vector = requireNotNull(javaClass.getResourceAsStream("/v1-basic-message.json"))
            .bufferedReader(StandardCharsets.UTF_8)
            .use { it.readText() }

        val payload = """{"body":"hello","to":"recipient"}"""
        val publicKey = "A".repeat(59)
        val canonical = CanonicalEventCodec.unsignedJson(
            UnsignedEvent(
                version = 1,
                type = "message.created",
                authorPublicKey = publicKey,
                createdAtEpochMs = 1_700_000_000_000,
                expiresAtEpochMs = null,
                payloadCanonicalJson = payload
            )
        )

        assertTrue(vector.contains(canonical))
        assertTrue(vector.contains(Hashing.sha256Url(canonical)))
        assertEquals("4A4ijpkPbkIhJtoaGOT2ZPzW0mF6w_ZGNEG7wV58nAE", Hashing.sha256Url(canonical))
    }
}
