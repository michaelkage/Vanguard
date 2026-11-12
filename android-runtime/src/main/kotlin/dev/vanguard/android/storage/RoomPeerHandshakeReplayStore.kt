package dev.vanguard.android.storage

import android.os.Looper
import dev.vanguard.protocol.ReplayClaimStore
import java.util.concurrent.Callable

/**
 * Durable replay-claim store for the Android protocol runtime.
 *
 * Claims and the persisted clock high-water mark are committed in one Room
 * transaction. Calls are synchronous because the protocol reference accepts a
 * synchronous replay-guard contract; callers must invoke it off the main thread.
 */
class RoomPeerHandshakeReplayStore(
    private val database: VanguardDatabase
) : ReplayClaimStore {
    override fun <T> transaction(block: ReplayClaimStore.Transaction.() -> T): T {
        check(Looper.myLooper() != Looper.getMainLooper()) {
            "Peer handshake replay claims must run off the Android main thread"
        }

        return database.runInTransaction(Callable {
            val dao = database.vanguardDao()
            val transaction = object : ReplayClaimStore.Transaction {
                override fun readLastObservedEpochMs(): Long? =
                    dao.getLastReplayClockEpochMs()

                override fun writeLastObservedEpochMs(value: Long) {
                    dao.putReplayClock(PeerHandshakeReplayClock(
                        lastObservedEpochMs = value
                    ))
                }

                override fun deleteExpiredClaims(nowEpochMs: Long) {
                    dao.deleteExpiredReplayClaims(nowEpochMs)
                }

                override fun countActiveClaims(): Int = dao.countReplayClaims()

                override fun insertClaim(claimId: String, expiresAtEpochMs: Long): Boolean =
                    dao.insertReplayClaim(
                        PeerHandshakeReplayClaim(claimId, expiresAtEpochMs)
                    ) != -1L
            }
            transaction.block()
        })
    }
}
