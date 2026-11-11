package dev.vanguard.protocol

import java.nio.charset.StandardCharsets
import kotlin.test.Test
import kotlin.test.assertEquals
import org.json.JSONObject

class ProtocolVectorTest {
    @Test
    fun `shared v1 message vector matches canonical encoder and event ID`() {
        val fixtureText = requireNotNull(javaClass.getResourceAsStream("/v1-basic-message.json"))
            .bufferedReader(StandardCharsets.UTF_8)
            .use { it.readText() }
        val fixture = JSONObject(fixtureText)

        val canonical = CanonicalEventCodec.unsignedJson(
            UnsignedEvent(
                version = fixture.getInt("version"),
                type = fixture.getString("type"),
                authorPublicKey = fixture.getString("authorPublicKey"),
                createdAtEpochMs = fixture.getLong("createdAtEpochMs"),
                expiresAtEpochMs = null,
                payloadCanonicalJson = fixture.getString("payloadCanonicalJson")
            )
        )

        assertEquals(fixture.getString("unsignedCanonicalJson"), canonical)
        assertEquals(fixture.getString("eventId"), Hashing.sha256Url(canonical.toByteArray(StandardCharsets.UTF_8)))
    }
}
