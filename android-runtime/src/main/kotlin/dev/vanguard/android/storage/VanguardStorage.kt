package dev.vanguard.android.storage

import android.content.Context
import androidx.room.Room

object VanguardStorage {
    private const val DATABASE_NAME = "vanguard.db"

    fun open(context: Context): VanguardDatabase =
        Room.databaseBuilder(
            context.applicationContext,
            VanguardDatabase::class.java,
            DATABASE_NAME
        ).build()
}
