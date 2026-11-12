package dev.vanguard.protocol

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DurableReplayGuardTest {
    private class MemoryReplayClaimStore : ReplayClaimStore {
        private val lock = Any()
        private var lastObservedEpochMs: Long? = null
        private val claims = mutableMapOf<String, Long>()

        override fun <T> transaction(block: ReplayClaimStore.Transaction.() -> T): T =
            synchronized(lock) {
                val transaction = object : ReplayClaimStore.Transaction {
                    override fun readLastObservedEpochMs(): Long? = lastObservedEpochMs

                    override fun writeLastObservedEpochMs(value: Long) {
                        lastObservedEpochMs = value
                    }

                    override fun deleteExpiredClaims(nowEpochMs: Long) {
                        claims.entries.removeAll { it.value <= nowEpochMs }
                    }

                    override fun countActiveClaims(): Int = claims.size

                    override fun insertClaim(claimId: String, expiresAtEpochMs: Long): Boolean {
                        if (claims.containsKey(claimId)) return false
                        claims[claimId] = expiresAtEpochMs
                        return true
                    }
                }
                transaction.block()
            }
    }

    @Test
    fun `claim survives guard recreation and rejects replay`() {
        val store = MemoryReplayClaimStore()
        var now = 10_000L
        val first = DurableReplayGuard(store, { now })
        val second = DurableReplayGuard(store, { now })
        val sessionId = ByteArray(16) { 1 }
        val nonce = ByteArray(32) { 2 }

        assertTrue(first.claim(sessionId, nonce))
        assertFalse(second.claim(sessionId, nonce))
    }

    @Test
    fun `expired claims are pruned at the exact retention boundary`() {
        val store = MemoryReplayClaimStore()
        var now = 10_000L
        val guard = DurableReplayGuard(store, { now }, retentionMillis = 5_000L)
        val sessionId = ByteArray(16) { 3 }
        val nonce = ByteArray(32) { 4 }

        assertTrue(guard.claim(sessionId, nonce))
        now = 14_999L
        assertFalse(guard.claim(sessionId, nonce))
        now = 15_000L
        assertTrue(guard.claim(sessionId, nonce))
    }

    @Test
    fun `persisted high water rejects wall clock rollback`() {
        val store = MemoryReplayClaimStore()
        var now = 20_000L
        val guard = DurableReplayGuard(store, { now })
        assertTrue(guard.claim(ByteArray(16) { 5 }, ByteArray(32) { 6 }))

        now = 19_999L
        assertFailsWith<IllegalArgumentException> {
            guard.claim(ByteArray(16) { 7 }, ByteArray(32) { 8 })
        }
    }

    @Test
    fun `capacity exhaustion fails closed`() {
        val store = MemoryReplayClaimStore()
        var now = 30_000L
        val guard = DurableReplayGuard(store, { now }, retentionMillis = 10_000L, capacity = 1)

        assertTrue(guard.claim(ByteArray(16) { 9 }, ByteArray(32) { 10 }))
        assertFalse(guard.claim(ByteArray(16) { 11 }, ByteArray(32) { 12 }))
        now += 10_000L
        assertTrue(guard.claim(ByteArray(16) { 11 }, ByteArray(32) { 12 }))
    }

    @Test
    fun `invalid identifiers and clock values are rejected`() {
        val store = MemoryReplayClaimStore()
        var now = 1L
        val guard = DurableReplayGuard(store, { now })

        assertFailsWith<IllegalArgumentException> {
            guard.claim(ByteArray(15), ByteArray(32))
        }
        assertFailsWith<IllegalArgumentException> {
            guard.claim(ByteArray(16), ByteArray(31))
        }
        now = -1L
        assertFailsWith<IllegalArgumentException> {
            guard.claim(ByteArray(16), ByteArray(32))
        }
    }

    @Test
    fun `retention is explicit and reports the configured guarantee`() {
        val guard = DurableReplayGuard(
            MemoryReplayClaimStore(),
            { 1_000L },
            retentionMillis = 240_000L
        )
        assertEquals(240_000L, guard.retentionMillis)
    }
}
