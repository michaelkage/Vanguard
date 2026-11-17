package dev.vanguard.protocol

import java.nio.charset.StandardCharsets

/**
 * Fixed-field deterministic encoder. Field order and escaping are part of protocol v1.
 * Payload JSON must already be canonicalized by the event-type layer.
 */
object CanonicalEventCodec {
    fun unsignedBytes(event: UnsignedEvent): ByteArray =
        unsignedJson(event).toByteArray(StandardCharsets.UTF_8)

    fun signedBytes(event: EventEnvelope): ByteArray = unsignedBytes(
        UnsignedEvent(
            event.version,
            event.type,
            event.authorPublicKey,
            event.createdAtEpochMs,
            event.expiresAtEpochMs,
            event.payloadCanonicalJson
        )
    )

    fun unsignedJson(event: UnsignedEvent): String {
        validate(event)
        return buildString {
            append('{')
            appendField("version", event.version.toString()); append(',')
            appendField("type", quote(event.type)); append(',')
            appendField("authorPublicKey", quote(event.authorPublicKey)); append(',')
            appendField("createdAtEpochMs", event.createdAtEpochMs.toString()); append(',')
            appendField("expiresAtEpochMs", event.expiresAtEpochMs?.toString() ?: "null"); append(',')
            appendField("payload", event.payloadCanonicalJson)
            append('}')
        }
    }

    private fun StringBuilder.appendField(name: String, encodedValue: String) {
        append(quote(name))
        append(':')
        append(encodedValue)
    }

    private fun validate(event: UnsignedEvent) {
        if (event.version != ProtocolVersion.CURRENT) throw ProtocolException.UnsupportedVersion
        if (!event.type.matches(Regex("[a-z][a-z0-9_.-]{0,63}"))) {
            throw ProtocolException.InvalidField
        }
        if (event.authorPublicKey.isBlank() || event.createdAtEpochMs < 0) {
            throw ProtocolException.InvalidField
        }
        if (event.expiresAtEpochMs != null &&
            event.expiresAtEpochMs <= event.createdAtEpochMs
        ) {
            throw ProtocolException.InvalidField
        }
        val payload = event.payloadCanonicalJson.trim()
        if (!payload.startsWith("{") || !payload.endsWith("}")) {
            throw ProtocolException.InvalidField
        }
    }

    private fun quote(value: String): String = buildString {
        append('"')
        value.forEach { character ->
            when (character) {
                '"' -> append("\\\"")
                '\\' -> append("\\\\")
                '\b' -> append("\\b")
                '\u000C' -> append("\\f")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> if (character.code < 0x20) {
                    append("\\u%04x".format(character.code))
                } else {
                    append(character)
                }
            }
        }
        append('"')
    }
}
