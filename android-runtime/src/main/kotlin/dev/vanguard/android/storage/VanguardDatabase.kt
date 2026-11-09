package dev.vanguard.android.storage

import androidx.room.Database
import androidx.room.RoomDatabase

@Database(
    entities = [StoredEvent::class, RelayQueueEntry::class],
    version = 1,
    exportSchema = true
)
abstract class VanguardDatabase : RoomDatabase() {
    abstract fun vanguardDao(): VanguardDao
}
