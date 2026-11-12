package dev.vanguard.android.storage

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    tableName = "peer_handshake_replay_claims",
    indices = [Index(value = ["expiresAtEpochMs"])]
)
data class PeerHandshakeReplayClaim(
    @PrimaryKey val claimId: String,
    val expiresAtEpochMs: Long
)

@Entity(tableName = "peer_handshake_replay_clock")
data class PeerHandshakeReplayClock(
    @PrimaryKey val id: Int = SINGLETON_ID,
    val lastObservedEpochMs: Long
) {
    companion object {
        const val SINGLETON_ID = 1
    }
}
