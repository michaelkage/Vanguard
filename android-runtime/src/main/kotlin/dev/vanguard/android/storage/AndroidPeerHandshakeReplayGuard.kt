package dev.vanguard.android.storage

import android.content.Context
import dev.vanguard.protocol.AuthenticatedSessionProtocol
import dev.vanguard.protocol.DurableReplayGuard

/**
 * Creates the Android durable replay guard over Vanguard's Room database.
 *
 * The supplied epoch clock must be the same rollback-aware clock used by the
 * peer handshake time policy. Claims are synchronous and must be made from a
 * worker thread; RoomPeerHandshakeReplayStore enforces this requirement.
 */
fun createAndroidPeerHandshakeReplayGuard(
    context: Context,
    epochClock: () -> Long,
    retentionMillis: Long = AuthenticatedSessionProtocol.MIN_REPLAY_RETENTION_MILLIS,
    capacity: Int = 100_000
): DurableReplayGuard = DurableReplayGuard(
    store = RoomPeerHandshakeReplayStore(VanguardStorage.open(context)),
    epochClock = epochClock,
    retentionMillis = retentionMillis,
    capacity = capacity
)
