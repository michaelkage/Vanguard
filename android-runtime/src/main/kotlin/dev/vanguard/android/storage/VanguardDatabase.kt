package dev.vanguard.android.storage

import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

@Database(
    entities = [
        StoredEvent::class,
        RelayQueueEntry::class,
        PeerHandshakeReplayClaim::class,
        PeerHandshakeReplayClock::class
    ],
    version = 2,
    exportSchema = true
)
abstract class VanguardDatabase : RoomDatabase() {
    abstract fun vanguardDao(): VanguardDao

    companion object {
        val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(database: SupportSQLiteDatabase) {
                database.execSQL(
                    """
                    CREATE TABLE IF NOT EXISTS peer_handshake_replay_claims (
                        claimId TEXT NOT NULL,
                        expiresAtEpochMs INTEGER NOT NULL,
                        PRIMARY KEY(claimId)
                    )
                    """.trimIndent()
                )
                database.execSQL(
                    """
                    CREATE INDEX IF NOT EXISTS index_peer_handshake_replay_claims_expiresAtEpochMs
                    ON peer_handshake_replay_claims(expiresAtEpochMs)
                    """.trimIndent()
                )
                database.execSQL(
                    """
                    CREATE TABLE IF NOT EXISTS peer_handshake_replay_clock (
                        id INTEGER NOT NULL,
                        lastObservedEpochMs INTEGER NOT NULL,
                        PRIMARY KEY(id)
                    )
                    """.trimIndent()
                )
            }
        }
    }
}
