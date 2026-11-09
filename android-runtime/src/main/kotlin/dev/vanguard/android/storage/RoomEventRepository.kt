package dev.vanguard.android.storage

import androidx.room.withTransaction
import dev.vanguard.protocol.EventEnvelope

/**
 * Durable Android event storage.
 *
 * The caller MUST verify an incoming envelope with EventProtocol before calling
 * [storeVerifiedAndQueue]. This repository persists bytes and queue state; it is
 * not an identity, signature, enrollment, or revocation authority.
 */
class RoomEventRepository(
    private val database: VanguardDatabase
) {
    private val dao = database.vanguardDao()

    /**
     * Inserts a verified event and its relay work item atomically.
     * Returns false when the event ID was already present.
     */
    suspend fun storeVerifiedAndQueue(
        event: EventEnvelope,
        receivedAtEpochMs: Long
    ): Boolean {
        require(receivedAtEpochMs >= 0) { "receivedAtEpochMs must be non-negative" }

        return database.withTransaction {
            val insertedRowId = dao.insertEvent(StoredEvent.from(event))
            if (insertedRowId == -1L) {
                false
            } else {
                dao.enqueueRelay(
                    RelayQueueEntry(
                        eventId = event.id,
                        enqueuedAtEpochMs = receivedAtEpochMs
                    )
                )
                true
            }
        }
    }

    suspend fun get(eventId: String): EventEnvelope? =
        dao.getEvent(eventId)?.toEnvelope()

    suspend fun all(): List<EventEnvelope> =
        dao.getAllEvents().map(StoredEvent::toEnvelope)

    suspend fun nextRelayBatch(nowEpochMs: Long, limit: Int = 32): List<EventEnvelope> {
        require(nowEpochMs >= 0) { "nowEpochMs must be non-negative" }
        require(limit in 1..256) { "limit must be between 1 and 256" }
        return dao.getNextRelayBatch(nowEpochMs, limit).map(StoredEvent::toEnvelope)
    }

    suspend fun acknowledgeRelay(eventId: String) {
        dao.acknowledgeRelay(eventId)
    }

    suspend fun deferRelay(
        eventId: String,
        nextAttemptAtEpochMs: Long,
        error: String?
    ) {
        require(nextAttemptAtEpochMs >= 0) {
            "nextAttemptAtEpochMs must be non-negative"
        }
        dao.deferRelay(eventId, nextAttemptAtEpochMs, error?.take(512))
    }

    suspend fun pendingRelayCount(): Int = dao.pendingRelayCount()
}
