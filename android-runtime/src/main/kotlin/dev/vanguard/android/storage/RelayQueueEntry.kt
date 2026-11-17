package dev.vanguard.android.storage

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index

@Entity(
    tableName = "relay_queue",
    primaryKeys = ["eventId"],
    foreignKeys = [
        ForeignKey(
            entity = StoredEvent::class,
            parentColumns = ["id"],
            childColumns = ["eventId"],
            onDelete = ForeignKey.CASCADE
        )
    ],
    indices = [Index(value = ["nextAttemptAtEpochMs", "enqueuedAtEpochMs"])]
)
data class RelayQueueEntry(
    val eventId: String,
    val enqueuedAtEpochMs: Long,
    val attempts: Int = 0,
    val nextAttemptAtEpochMs: Long = enqueuedAtEpochMs,
    val lastError: String? = null
)
