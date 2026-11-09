package dev.vanguard.android.storage

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query

@Dao
interface VanguardDao {
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertEvent(event: StoredEvent): Long

    @Query("SELECT * FROM events WHERE id = :eventId LIMIT 1")
    suspend fun getEvent(eventId: String): StoredEvent?

    @Query("SELECT * FROM events ORDER BY createdAtEpochMs ASC")
    suspend fun getAllEvents(): List<StoredEvent>

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun enqueueRelay(entry: RelayQueueEntry): Long

    @Query(
        """
        SELECT events.* FROM events
        INNER JOIN relay_queue ON relay_queue.eventId = events.id
        WHERE relay_queue.nextAttemptAtEpochMs <= :nowEpochMs
        ORDER BY relay_queue.enqueuedAtEpochMs ASC
        LIMIT :limit
        """
    )
    suspend fun getNextRelayBatch(nowEpochMs: Long, limit: Int): List<StoredEvent>

    @Query("DELETE FROM relay_queue WHERE eventId = :eventId")
    suspend fun acknowledgeRelay(eventId: String)

    @Query(
        """
        UPDATE relay_queue
        SET attempts = attempts + 1,
            nextAttemptAtEpochMs = :nextAttemptAtEpochMs,
            lastError = :error
        WHERE eventId = :eventId
        """
    )
    suspend fun deferRelay(
        eventId: String,
        nextAttemptAtEpochMs: Long,
        error: String?
    )

    @Query("SELECT COUNT(*) FROM relay_queue")
    suspend fun pendingRelayCount(): Int
}
