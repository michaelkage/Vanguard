package dev.vanguard.android.storage

import android.content.Context
import androidx.room.Room

object VanguardStorage {
    private const val DATABASE_NAME = "vanguard.db"

    @Volatile
    private var instance: VanguardDatabase? = null

    fun open(context: Context): VanguardDatabase =
        instance ?: synchronized(this) {
            instance ?: Room.databaseBuilder(
                context.applicationContext,
                VanguardDatabase::class.java,
                DATABASE_NAME
            )
                .addMigrations(VanguardDatabase.MIGRATION_1_2)
                .build()
                .also { instance = it }
        }
}
