import type { SignedEventEnvelope } from "../protocol/envelope";
import { assertEnvelopeShape } from "../protocol/envelope";
import { getDatabase } from "./database";

export interface SignatureVerifier {
  verify(envelope: SignedEventEnvelope): Promise<boolean>;
}

export interface RelayBatchItem {
  readonly envelope: SignedEventEnvelope;
  readonly hopCount: number;
  readonly maxHops: number;
}

export class EventVerificationError extends Error {
  constructor() {
    super("Event signature verification failed");
    this.name = "EventVerificationError";
  }
}

/** Persists only events that pass the injected native cryptographic verifier. */
export async function storeVerifiedEvent(
  candidate: unknown,
  verifier: SignatureVerifier,
  options: { readonly nowEpochMs: number; readonly maxHops?: number }
): Promise<boolean> {
  assertEnvelopeShape(candidate);
  const envelope = candidate;

  if (envelope.expiresAtEpochMs !== null && envelope.expiresAtEpochMs <= options.nowEpochMs) {
    throw new Error("Expired events cannot enter the active event store");
  }
  if (!(await verifier.verify(envelope))) throw new EventVerificationError();

  const maxHops = options.maxHops ?? 5;
  if (!Number.isSafeInteger(maxHops) || maxHops < 1 || maxHops > 8) {
    throw new RangeError("maxHops must be an integer between 1 and 8");
  }

  const database = await getDatabase();
  let inserted = false;

  await database.withTransactionAsync(async () => {
    const result = await database.runAsync(
      "INSERT OR IGNORE INTO events (event_id, envelope_json, author_public_key, created_at_ms, expires_at_ms, received_at_ms, sync_state) VALUES (?, ?, ?, ?, ?, ?, 'pending')",
      envelope.id,
      JSON.stringify(envelope),
      envelope.authorPublicKey,
      envelope.createdAtEpochMs,
      envelope.expiresAtEpochMs,
      options.nowEpochMs
    );
    inserted = result.changes > 0;

    if (inserted) {
      await database.runAsync(
        "INSERT INTO relay_queue (event_id, hop_count, max_hops, attempts, next_attempt_at_ms, queued_at_ms) VALUES (?, 0, ?, 0, ?, ?)",
        envelope.id,
        maxHops,
        options.nowEpochMs,
        options.nowEpochMs
      );
    }
  });

  return inserted;
}

export async function getRelayBatchForPeer(
  peerDeviceId: string,
  nowEpochMs: number,
  limit = 32
): Promise<RelayBatchItem[]> {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
    throw new RangeError("Relay batch limit must be between 1 and 100");
  }

  const database = await getDatabase();
  const rows = await database.getAllAsync<{
    envelope_json: string;
    hop_count: number;
    max_hops: number;
  }>(
    "SELECT events.envelope_json, relay_queue.hop_count, relay_queue.max_hops FROM relay_queue INNER JOIN events ON events.event_id = relay_queue.event_id WHERE relay_queue.next_attempt_at_ms <= ? AND relay_queue.hop_count < relay_queue.max_hops AND (events.expires_at_ms IS NULL OR events.expires_at_ms > ?) AND NOT EXISTS (SELECT 1 FROM peer_sync_history WHERE peer_sync_history.event_id = events.event_id AND peer_sync_history.peer_device_id = ?) ORDER BY relay_queue.queued_at_ms ASC LIMIT ?",
    nowEpochMs,
    nowEpochMs,
    peerDeviceId,
    limit
  );

  return rows.map(row => ({
    envelope: JSON.parse(row.envelope_json) as SignedEventEnvelope,
    hopCount: row.hop_count,
    maxHops: row.max_hops
  }));
}

export async function recordPeerDelivery(
  eventId: string,
  peerDeviceId: string,
  deliveredAtEpochMs: number
): Promise<boolean> {
  const database = await getDatabase();
  let recorded = false;

  await database.withTransactionAsync(async () => {
    const inserted = await database.runAsync(
      "INSERT OR IGNORE INTO peer_sync_history (peer_device_id, event_id, delivered_at_ms) SELECT ?, event_id, ? FROM events WHERE event_id = ?",
      peerDeviceId,
      deliveredAtEpochMs,
      eventId
    );
    if (inserted.changes === 0) return;

    const updated = await database.runAsync(
      "UPDATE relay_queue SET hop_count = hop_count + 1, attempts = attempts + 1, last_attempt_at_ms = ?, next_attempt_at_ms = ? WHERE event_id = ? AND hop_count < max_hops",
      deliveredAtEpochMs,
      deliveredAtEpochMs,
      eventId
    );
    recorded = updated.changes > 0;
  });

  return recorded;
}

export async function deferRelay(eventId: string, nowEpochMs: number): Promise<void> {
  const database = await getDatabase();
  await database.runAsync(
    "UPDATE relay_queue SET attempts = attempts + 1, last_attempt_at_ms = ?, next_attempt_at_ms = ? + MIN(3600000, 1000 * (1 << MIN(attempts, 10))) WHERE event_id = ?",
    nowEpochMs,
    nowEpochMs,
    eventId
  );
}

export async function getCloudSyncBatch(
  nowEpochMs: number,
  limit = 50
): Promise<SignedEventEnvelope[]> {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 200) {
    throw new RangeError("Cloud sync batch limit must be between 1 and 200");
  }

  const database = await getDatabase();
  const rows = await database.getAllAsync<{ envelope_json: string }>(
    "SELECT envelope_json FROM events WHERE sync_state = 'pending' AND (expires_at_ms IS NULL OR expires_at_ms > ?) ORDER BY received_at_ms ASC LIMIT ?",
    nowEpochMs,
    limit
  );
  return rows.map(row => JSON.parse(row.envelope_json) as SignedEventEnvelope);
}

export async function markCloudConfirmed(eventIds: readonly string[]): Promise<void> {
  if (eventIds.length === 0) return;
  if (eventIds.length > 200) {
    throw new RangeError("Cloud acknowledgement batch cannot exceed 200 events");
  }

  const database = await getDatabase();
  await database.withTransactionAsync(async () => {
    for (const eventId of eventIds) {
      await database.runAsync(
        "UPDATE events SET sync_state = 'confirmed' WHERE event_id = ?",
        eventId
      );
      await database.runAsync("DELETE FROM relay_queue WHERE event_id = ?", eventId);
    }
  });
}

export async function pruneExpiredEvents(nowEpochMs: number): Promise<number> {
  const database = await getDatabase();
  const result = await database.runAsync(
    "DELETE FROM events WHERE expires_at_ms IS NOT NULL AND expires_at_ms <= ?",
    nowEpochMs
  );
  return result.changes;
}
