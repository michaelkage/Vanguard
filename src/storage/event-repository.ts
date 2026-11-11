import type { SignedEventEnvelope } from "../protocol/envelope";
import { assertEnvelopeShape } from "../protocol/envelope";
import { getDatabase } from "./database";

export const MAX_LOGICAL_EVENT_STORE_BYTES = 50 * 1024 * 1024;

export class StorageQuotaExceededError extends Error {
  constructor() {
    super("Vanguard's local event store has reached its 50 MiB logical limit");
    this.name = "StorageQuotaExceededError";
  }
}

export interface SignatureVerifier {
  verify(envelope: SignedEventEnvelope): Promise<boolean>;
}

export interface RelayBatchItem {
  readonly envelope: SignedEventEnvelope;
  /** Next hop depth to include in mutable relay metadata. */
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
  options: {
    readonly nowEpochMs: number;
    readonly maxHops?: number;
    readonly receivedHopCount?: number;
    readonly receivedFromPeerId?: string;
  }
): Promise<boolean> {
  assertEnvelopeShape(candidate);
  const envelope = candidate;

  if (!Number.isSafeInteger(options.nowEpochMs) || options.nowEpochMs < 0) {
    throw new RangeError("nowEpochMs must be a non-negative safe integer");
  }

  const maxHops = options.maxHops ?? 5;
  if (!Number.isSafeInteger(maxHops) || maxHops < 1 || maxHops > 8) {
    throw new RangeError("maxHops must be an integer between 1 and 8");
  }

  const receivedHopCount = options.receivedHopCount ?? 0;
  if (!Number.isSafeInteger(receivedHopCount) || receivedHopCount < 0 || receivedHopCount > maxHops) {
    throw new RangeError("receivedHopCount must be between zero and maxHops");
  }

  if (options.receivedFromPeerId !== undefined && options.receivedFromPeerId.length === 0) {
    throw new TypeError("receivedFromPeerId cannot be empty");
  }
  if (envelope.expiresAtEpochMs !== null && envelope.expiresAtEpochMs <= options.nowEpochMs) {
    throw new Error("Expired events cannot enter the active event store");
  }
  if (!(await verifier.verify(envelope))) throw new EventVerificationError();

  const database = await getDatabase();
  const serializedEnvelope = JSON.stringify(envelope);
  let inserted = false;
  let quotaExceeded = false;

  await database.withTransactionAsync(async () => {
    const existing = await database.getFirstAsync<{ event_id: string }>(
      "SELECT event_id FROM events WHERE event_id = ?",
      envelope.id
    );
    if (existing) {
      if (options.receivedFromPeerId !== undefined) {
        await database.runAsync(
          "INSERT OR IGNORE INTO peer_sync_history (peer_device_id, event_id, delivered_at_ms) VALUES (?, ?, ?)",
          options.receivedFromPeerId,
          envelope.id,
          options.nowEpochMs
        );
      }
      return;
    }

    await database.runAsync(
      "DELETE FROM events WHERE expires_at_ms IS NOT NULL AND expires_at_ms <= ?",
      options.nowEpochMs
    );

    const sizeRow = await database.getFirstAsync<{ bytes: number }>(
      "SELECT length(CAST(? AS BLOB)) AS bytes",
      serializedEnvelope
    );
    const incomingBytes = sizeRow?.bytes ?? 0;
    const totalRow = await database.getFirstAsync<{ bytes: number }>(
      "SELECT COALESCE(SUM(length(CAST(envelope_json AS BLOB))), 0) AS bytes FROM events"
    );
    let storedBytes = totalRow?.bytes ?? 0;

    if (storedBytes + incomingBytes > MAX_LOGICAL_EVENT_STORE_BYTES) {
      const confirmedRows = await database.getAllAsync<{ event_id: string; bytes: number }>(
        "SELECT event_id, length(CAST(envelope_json AS BLOB)) AS bytes FROM events WHERE sync_state = 'confirmed' ORDER BY received_at_ms ASC"
      );

      for (const row of confirmedRows) {
        if (storedBytes + incomingBytes <= MAX_LOGICAL_EVENT_STORE_BYTES) break;
        await database.runAsync("DELETE FROM events WHERE event_id = ?", row.event_id);
        storedBytes -= row.bytes;
      }
    }

    if (storedBytes + incomingBytes > MAX_LOGICAL_EVENT_STORE_BYTES) {
      quotaExceeded = true;
      return;
    }

    await database.runAsync(
      "INSERT INTO events (event_id, envelope_json, author_public_key, created_at_ms, expires_at_ms, received_at_ms, sync_state) VALUES (?, ?, ?, ?, ?, ?, 'pending')",
      envelope.id,
      serializedEnvelope,
      envelope.authorPublicKey,
      envelope.createdAtEpochMs,
      envelope.expiresAtEpochMs,
      options.nowEpochMs
    );
    inserted = true;

    if (receivedHopCount < maxHops) {
      await database.runAsync(
        "INSERT INTO relay_queue (event_id, hop_count, max_hops, attempts, next_attempt_at_ms, queued_at_ms) VALUES (?, ?, ?, 0, ?, ?)",
        envelope.id,
        receivedHopCount,
        maxHops,
        options.nowEpochMs,
        options.nowEpochMs
      );
    }

    if (options.receivedFromPeerId !== undefined) {
      await database.runAsync(
        "INSERT INTO peer_sync_history (peer_device_id, event_id, delivered_at_ms) VALUES (?, ?, ?)",
        options.receivedFromPeerId,
        envelope.id,
        options.nowEpochMs
      );
    }
  });

  if (quotaExceeded) throw new StorageQuotaExceededError();
  return inserted;
}

export async function getRelayBatchForPeer(
  peerDeviceId: string,
  nowEpochMs: number,
  limit = 32
): Promise<RelayBatchItem[]> {
  if (peerDeviceId.length === 0) throw new TypeError("peerDeviceId cannot be empty");
  if (!Number.isSafeInteger(nowEpochMs) || nowEpochMs < 0) {
    throw new RangeError("nowEpochMs must be a non-negative safe integer");
  }
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
    throw new RangeError("Relay batch limit must be between 1 and 100");
  }

  const database = await getDatabase();
  const rows = await database.getAllAsync<{
    envelope_json: string;
    hop_count: number;
    max_hops: number;
  }>(
    "SELECT events.envelope_json, relay_queue.hop_count + 1 AS hop_count, relay_queue.max_hops FROM relay_queue INNER JOIN events ON events.event_id = relay_queue.event_id WHERE relay_queue.next_attempt_at_ms <= ? AND relay_queue.hop_count < relay_queue.max_hops AND (events.expires_at_ms IS NULL OR events.expires_at_ms > ?) AND NOT EXISTS (SELECT 1 FROM peer_sync_history WHERE peer_sync_history.event_id = events.event_id AND peer_sync_history.peer_device_id = ?) ORDER BY relay_queue.queued_at_ms ASC LIMIT ?",
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

/** Records a successful peer transfer and advances the local relay depth. */
export async function recordPeerDelivery(
  eventId: string,
  peerDeviceId: string,
  deliveredAtEpochMs: number
): Promise<boolean> {
  if (!/^[A-Za-z0-9_-]{43}$/.test(eventId)) throw new TypeError("Invalid event ID");
  if (peerDeviceId.length === 0) throw new TypeError("peerDeviceId cannot be empty");
  if (!Number.isSafeInteger(deliveredAtEpochMs) || deliveredAtEpochMs < 0) {
    throw new RangeError("deliveredAtEpochMs must be a non-negative safe integer");
  }

  const database = await getDatabase();
  let recorded = false;

  await database.withTransactionAsync(async () => {
    const updated = await database.runAsync(
      "UPDATE relay_queue SET hop_count = hop_count + 1, attempts = attempts + 1, last_attempt_at_ms = ?, next_attempt_at_ms = ? WHERE event_id = ? AND hop_count < max_hops AND EXISTS (SELECT 1 FROM events WHERE events.event_id = relay_queue.event_id) AND NOT EXISTS (SELECT 1 FROM peer_sync_history WHERE peer_sync_history.event_id = relay_queue.event_id AND peer_sync_history.peer_device_id = ?)",
      deliveredAtEpochMs,
      deliveredAtEpochMs,
      eventId,
      peerDeviceId
    );
    if (updated.changes === 0) return;

    await database.runAsync(
      "INSERT INTO peer_sync_history (peer_device_id, event_id, delivered_at_ms) VALUES (?, ?, ?)",
      peerDeviceId,
      eventId,
      deliveredAtEpochMs
    );
    recorded = true;
  });

  return recorded;
}

export async function deferRelay(eventId: string, nowEpochMs: number): Promise<void> {
  if (!/^[A-Za-z0-9_-]{43}$/.test(eventId)) throw new TypeError("Invalid event ID");
  if (!Number.isSafeInteger(nowEpochMs) || nowEpochMs < 0) {
    throw new RangeError("nowEpochMs must be a non-negative safe integer");
  }

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
  if (!Number.isSafeInteger(nowEpochMs) || nowEpochMs < 0) {
    throw new RangeError("nowEpochMs must be a non-negative safe integer");
  }
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

/** Call only with event IDs explicitly acknowledged by the gateway response. */
export async function markCloudConfirmed(eventIds: readonly string[]): Promise<void> {
  if (eventIds.length === 0) return;
  if (eventIds.length > 200) {
    throw new RangeError("Cloud acknowledgement batch cannot exceed 200 events");
  }
  if (eventIds.some(id => !/^[A-Za-z0-9_-]{43}$/.test(id))) {
    throw new TypeError("Cloud acknowledgement contains an invalid event ID");
  }

  const database = await getDatabase();
  await database.withTransactionAsync(async () => {
    for (const eventId of new Set(eventIds)) {
      await database.runAsync(
        "UPDATE events SET sync_state = 'confirmed' WHERE event_id = ?",
        eventId
      );
    }
  });
}

export async function pruneExpiredEvents(nowEpochMs: number): Promise<number> {
  if (!Number.isSafeInteger(nowEpochMs) || nowEpochMs < 0) {
    throw new RangeError("nowEpochMs must be a non-negative safe integer");
  }
  const database = await getDatabase();
  const result = await database.runAsync(
    "DELETE FROM events WHERE expires_at_ms IS NOT NULL AND expires_at_ms <= ?",
    nowEpochMs
  );
  return result.changes;
}
