package dev.vanguard.android.storage

import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.vanguard.protocol.EventEnvelope
import dev.vanguard.protocol.ProtocolVersion
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class RoomEventRepositoryTest {
    private lateinit var db: VanguardDatabase
    private lateinit var repository: RoomEventRepository

    @Before
    fun createDb() {
        db = Room.inMemoryDatabaseProvider(
            ApplicationProvider.getApplicationContext(),
            VanguardDatabase::class.java
        ).allowMainThreadQueries().build()
        repository = RoomEventRepository(db)
    }

    @After
    fun closeDb() {
        db.close()
    }

    @Test
    fun storeAndRetrieveEvent() = runBlocking {
        val event = createTestEvent("id-1")
        val success = repository.storeVerifiedAndQueue(event, System.currentTimeMillis())

        assertTrue(success)
        val retrieved = repository.get("id-1")
        assertEquals(event, retrieved)
    }

    @Test
    fun deduplicatesById() = runBlocking {
        val event = createTestEvent("id-1")
        repository.storeVerifiedAndQueue(event, System.currentTimeMillis())
        val secondInsert = repository.storeVerifiedAndQueue(event, System.currentTimeMillis())

        assertFalse(secondInsert)
        assertEquals(1, repository.all().size)
    }

    @Test
    fun relayQueueFlow() = runBlocking {
        val event1 = createTestEvent("id-1")
        val event2 = createTestEvent("id-2")
        val now = 1000L

        repository.storeVerifiedAndQueue(event1, now)
        repository.storeVerifiedAndQueue(event2, now + 10)

        assertEquals(2, repository.pendingRelayCount())

        val batch = repository.nextRelayBatch(now + 100, limit = 10)
        assertEquals(2, batch.size)
        assertEquals("id-1", batch[0].id)

        repository.acknowledgeRelay("id-1")
        assertEquals(1, repository.pendingRelayCount())

        val nextBatch = repository.nextRelayBatch(now + 100, limit = 10)
        assertEquals(1, nextBatch.size)
        assertEquals("id-2", nextBatch[0].id)
    }

    @Test
    fun deferralAndRetry() = runBlocking {
        val event = createTestEvent("id-1")
        val now = 1000L
        repository.storeVerifiedAndQueue(event, now)

        // Defer for 1 minute
        repository.deferRelay("id-1", now + 60000, "Link down")

        // Should not be in batch before nextAttempt
        val batchBefore = repository.nextRelayBatch(now + 30000)
        assertTrue(batchBefore.isEmpty())

        // Should be in batch after nextAttempt
        val batchAfter = repository.nextRelayBatch(now + 70000)
        assertEquals(1, batchAfter.size)
    }

    private fun createTestEvent(id: String) = EventEnvelope(
        version = ProtocolVersion.CURRENT,
        id = id,
        type = "test.event",
        authorPublicKey = "pubkey",
        createdAtEpochMs = 123456789L,
        expiresAtEpochMs = null,
        payloadCanonicalJson = "{}",
        signature = "sig"
    )
}
