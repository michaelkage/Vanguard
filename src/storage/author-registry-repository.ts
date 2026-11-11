import { getDatabase } from "./database";

export type AuthorRegistrySnapshotWriteResult =
  | "installed"
  | "unchanged"
  | "stale"
  | "conflict";

function assertCampusId(campusId: string): void {
  if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(campusId)) {
    throw new TypeError("Invalid campus ID");
  }
}

/** Returns the locally cached signed snapshot. The caller must verify its signature. */
export async function loadAuthorRegistrySnapshot(campusId: string): Promise<unknown | null> {
  assertCampusId(campusId);
  const database = await getDatabase();
  const row = await database.getFirstAsync<{ snapshot_json: string }>(
    "SELECT snapshot_json FROM author_registry_snapshots WHERE campus_id = ?",
    campusId
  );
  if (!row) return null;

  try {
    return JSON.parse(row.snapshot_json) as unknown;
  } catch {
    throw new Error("Stored author registry snapshot is corrupted");
  }
}

/**
 * Atomically enforces monotonic snapshot sequence numbers per campus.
 * Same-sequence content changes are treated as equivocation, not an update.
 */
export async function saveAuthorRegistrySnapshotIfNewer(
  campusId: string,
  sequence: number,
  snapshotJson: string,
  installedAtEpochMs: number
): Promise<AuthorRegistrySnapshotWriteResult> {
  assertCampusId(campusId);
  if (!Number.isSafeInteger(sequence) || sequence < 1) {
    throw new RangeError("Snapshot sequence must be a positive safe integer");
  }
  if (!Number.isSafeInteger(installedAtEpochMs) || installedAtEpochMs < 0) {
    throw new RangeError("Snapshot installation time must be a non-negative safe integer");
  }
  if (snapshotJson.length === 0 || snapshotJson.length > 8 * 1024 * 1024) {
    throw new RangeError("Author registry snapshot exceeds the 8 MiB storage limit");
  }

  const database = await getDatabase();
  let result: AuthorRegistrySnapshotWriteResult = "installed";

  await database.withTransactionAsync(async () => {
    const existing = await database.getFirstAsync<{
      sequence: number;
      snapshot_json: string;
    }>(
      "SELECT sequence, snapshot_json FROM author_registry_snapshots WHERE campus_id = ?",
      campusId
    );

    if (existing && sequence < existing.sequence) {
      result = "stale";
      return;
    }
    if (existing && sequence === existing.sequence) {
      result = existing.snapshot_json === snapshotJson ? "unchanged" : "conflict";
      return;
    }

    if (existing) {
      await database.runAsync(
        "UPDATE author_registry_snapshots SET sequence = ?, snapshot_json = ?, installed_at_ms = ? WHERE campus_id = ? AND sequence < ?",
        sequence,
        snapshotJson,
        installedAtEpochMs,
        campusId,
        sequence
      );
    } else {
      await database.runAsync(
        "INSERT INTO author_registry_snapshots (campus_id, sequence, snapshot_json, installed_at_ms) VALUES (?, ?, ?, ?)",
        campusId,
        sequence,
        snapshotJson,
        installedAtEpochMs
      );
    }
  });

  return result;
}
