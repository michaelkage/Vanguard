package dev.vanguard.protocol

import java.nio.charset.StandardCharsets
import java.security.MessageDigest

/**
 * Transactional persistence boundary for replay claims.
 *
 * Implementations must commit the entire callback atomically and durably before
 * returning. A rollback or partial commit must never be reported as success.
 */
interface ReplayClaimStore {
    fun <T> transaction(block: Transaction.() -> T): T

    interface Transaction {
        fun readLastObservedEpochMs(): Long?
        fun writeLastObservedEpochMs(value: Long)
        fun deleteExpiredClaims(nowEpochMs: Long)
        fun countActiveClaims(): Int
        fun insertClaim(claimId: String, expiresAtEpochMs: Long): Boolean
    }
}

/**
 * Replay protection backed by a durable transactional store.
 *
 * The persisted high-water clock detects wall-clock rollback across process
 * restarts while the store remains intact. It is not a hardware-backed time
 * source and cannot protect against an attacker who can replace application
 * storage or compromise the device.
 */
class DurableReplayGuard(
    private val store: ReplayClaimStore,
    private val epochClock: () -> Long,
    override val retentionMillis: Long = AuthenticatedSessionProtocol.MIN_REPLAY_RETENTION_MILLIS,
    private val capacity: Int = 100_000
) : AuthenticatedSessionProtocol.ReplayGuard {
    init {
        require(retentionMillis in 1..86_400_000L) {
            "Replay retention must be between 1 ms and 24 hours"
        }
        require(capacity in 1..1_000_000) {
            "Replay capacity must be between 1 and 1000000 claims"
        }
    }

    override fun claim(sessionId: ByteArray, initiatorNonce: ByteArray): Boolean {
        require(sessionId.size == SESSION_ID_BYTES) { "Invalid replay-guard session ID" }
        require(initiatorNonce.size == NONCE_BYTES) { "Invalid replay-guard initiator nonce" }

        val claimId = claimId(sessionId, initiatorNonce)
        return store.transaction {
            // Read time only after acquiring the store transaction. Concurrent
            // calls therefore cannot observe timestamps out of commit order.
            val now = epochClock()
            require(now >= 0) { "Replay-guard clock must be non-negative" }
            val previous = readLastObservedEpochMs()
            require(previous == null || now >= previous) {
                "Replay-guard clock moved backwards across persisted state"
            }

            writeLastObservedEpochMs(now)
            deleteExpiredClaims(now)

            if (countActiveClaims() >= capacity) return@transaction false
            val expiresAt = if (Long.MAX_VALUE - now < retentionMillis) {
                Long.MAX_VALUE
            } else {
                now + retentionMillis
            }
            insertClaim(claimId, expiresAt)
        }
    }

    private fun claimId(sessionId: ByteArray, initiatorNonce: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(CLAIM_DOMAIN)
        digest.update(sessionId)
        digest.update(initiatorNonce)
        return digest.digest().joinToString("") { byte ->
            (byte.toInt() and 0xff).toString(16).padStart(2, '0')
        }
    }

    companion object {
        private const val SESSION_ID_BYTES = 16
        private const val NONCE_BYTES = 32
        private val CLAIM_DOMAIN =
            "VANGUARD_PEER_REPLAY_CLAIM_V1".toByteArray(StandardCharsets.US_ASCII)
    }
}
