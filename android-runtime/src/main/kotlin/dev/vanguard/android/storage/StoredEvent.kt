package dev.vanguard.android.storage

import androidx.room.Entity
import androidx.room.Index
import dev.vanguard.protocol.EventEnvelope

@Entity(
    tableName = "events",
    indices = [
        Index(value = ["createdAtEpochMs"]),
        Index(value = ["authorPublicKey"])
    ]
)
data class StoredEvent(
    @androidx.room.PrimaryKey val id: String,
    val version: Int,
    val type: String,
    val authorPublicKey: String,
    val createdAtEpochMs: Long,
    val expiresAtEpochMs: Long?,
    val payloadCanonicalJson: String,
    val signature: String
) {
    fun toEnvelope() = EventEnvelope(
        version = version,
        id = id,
        type = type,
        authorPublicKey = authorPublicKey,
        createdAtEpochMs = createdAtEpochMs,
        expiresAtEpochMs = expiresAtEpochMs,
        payloadCanonicalJson = payloadCanonicalJson,
        signature = signature
    )

    companion object {
        fun from(event: EventEnvelope) = StoredEvent(
            id = event.id,
            version = event.version,
            type = event.type,
            authorPublicKey = event.authorPublicKey,
            createdAtEpochMs = event.createdAtEpochMs,
            expiresAtEpochMs = event.expiresAtEpochMs,
            payloadCanonicalJson = event.payloadCanonicalJson,
            signature = event.signature
        )
    }
}
