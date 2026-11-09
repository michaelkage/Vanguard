package dev.vanguard.protocol

/** Immutable author-signed event. Relay metadata must remain outside this envelope. */
data class EventEnvelope(
    val version: Int,
    val id: String,
    val type: String,
    val authorPublicKey: String,
    val createdAtEpochMs: Long,
    val expiresAtEpochMs: Long?,
    /** Canonical JSON object supplied by the event-type layer. */
    val payloadCanonicalJson: String,
    val signature: String
)

data class UnsignedEvent(
    val version: Int,
    val type: String,
    val authorPublicKey: String,
    val createdAtEpochMs: Long,
    val expiresAtEpochMs: Long?,
    val payloadCanonicalJson: String
)

data class RelayReceipt(
    val eventId: String,
    val relayedByPublicKey: String,
    val receivedAtEpochMs: Long,
    val hopCount: Int
)
