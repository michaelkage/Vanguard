import * as Crypto from "expo-crypto";
import * as SecureStore from "expo-secure-store";
import * as SQLite from "expo-sqlite";

const DATABASE_NAME = "vanguard.db";
const DATABASE_KEY_NAME = "vanguard.sqlcipher.key.v1";
const SCHEMA_VERSION = 2;

let databasePromise: Promise<SQLite.SQLiteDatabase> | undefined;

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
}

async function getOrCreateDatabaseKey(): Promise<string> {
  const existing = await SecureStore.getItemAsync(DATABASE_KEY_NAME);
  if (existing !== null) {
    if (!/^[a-f0-9]{64}$/.test(existing)) {
      throw new Error("Stored database key has an invalid format");
    }
    return existing;
  }

  const generated = bytesToHex(Crypto.getRandomBytes(32));
  await SecureStore.setItemAsync(DATABASE_KEY_NAME, generated);
  return generated;
}

async function migrate(database: SQLite.SQLiteDatabase): Promise<void> {
  const versionRow = await database.getFirstAsync<{ user_version: number }>("PRAGMA user_version");
  const currentVersion = versionRow?.user_version ?? 0;

  if (currentVersion > SCHEMA_VERSION) {
    throw new Error("Database schema is newer than this application supports");
  }
  if (currentVersion === SCHEMA_VERSION) return;

  await database.withTransactionAsync(async () => {
    if (currentVersion < 1) {
      await database.execAsync(`
        CREATE TABLE events (
          event_id TEXT PRIMARY KEY NOT NULL,
          envelope_json TEXT NOT NULL,
          author_public_key TEXT NOT NULL,
          created_at_ms INTEGER NOT NULL,
          expires_at_ms INTEGER,
          received_at_ms INTEGER NOT NULL,
          sync_state TEXT NOT NULL CHECK (sync_state IN ('pending', 'confirmed'))
        );
        CREATE INDEX events_sync_state_idx ON events(sync_state, received_at_ms);
        CREATE INDEX events_expiry_idx ON events(expires_at_ms);
        CREATE TABLE relay_queue (
          event_id TEXT PRIMARY KEY NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
          hop_count INTEGER NOT NULL DEFAULT 0 CHECK (hop_count >= 0),
          max_hops INTEGER NOT NULL CHECK (max_hops BETWEEN 1 AND 8),
          attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
          next_attempt_at_ms INTEGER NOT NULL,
          last_attempt_at_ms INTEGER,
          queued_at_ms INTEGER NOT NULL
        );
        CREATE INDEX relay_queue_due_idx ON relay_queue(next_attempt_at_ms, queued_at_ms);
        CREATE TABLE peer_sync_history (
          peer_device_id TEXT NOT NULL,
          event_id TEXT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
          delivered_at_ms INTEGER NOT NULL,
          PRIMARY KEY (peer_device_id, event_id)
        );
      `);
      await database.execAsync("PRAGMA user_version = 1");
    }

    if (currentVersion < 2) {
      await database.execAsync(`
        CREATE TABLE author_registry_snapshots (
          campus_id TEXT PRIMARY KEY NOT NULL,
          sequence INTEGER NOT NULL CHECK (sequence > 0),
          snapshot_json TEXT NOT NULL,
          installed_at_ms INTEGER NOT NULL CHECK (installed_at_ms >= 0)
        );
      `);
      await database.execAsync("PRAGMA user_version = 2");
    }
  });
}

async function openEncryptedDatabase(): Promise<SQLite.SQLiteDatabase> {
  const key = await getOrCreateDatabaseKey();
  const database = await SQLite.openDatabaseAsync(DATABASE_NAME);

  try {
    // SQLite silently ignores unknown PRAGMAs. Fail closed if this binary was
    // built without SQLCipher instead of pretending the database is encrypted.
    const cipher = await database.getFirstAsync<{ cipher_version: string }>(
      "PRAGMA cipher_version"
    );
    if (typeof cipher?.cipher_version !== "string" || cipher.cipher_version.length === 0) {
      throw new Error(
        "SQLCipher is unavailable in this build. Rebuild with expo-sqlite useSQLCipher enabled."
      );
    }

    // The key is generated as lowercase hex, so interpolation cannot inject SQL.
    await database.execAsync(`PRAGMA key = "x'${key}'"`);
    await database.execAsync("PRAGMA cipher_memory_security = ON");
    await database.execAsync("PRAGMA foreign_keys = ON");
    await database.execAsync("PRAGMA journal_mode = WAL");
    await database.execAsync("PRAGMA synchronous = NORMAL");
    await migrate(database);
    return database;
  } catch (error) {
    await database.closeAsync();
    throw error;
  }
}

export function getDatabase(): Promise<SQLite.SQLiteDatabase> {
  if (!databasePromise) {
    databasePromise = openEncryptedDatabase().catch(error => {
      databasePromise = undefined;
      throw error;
    });
  }
  return databasePromise;
}
