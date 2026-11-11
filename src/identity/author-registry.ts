import { canonicalizeJson } from "../protocol/canonical-json";

export type AuthorRegistryStatus = "active" | "suspended" | "revoked";

export interface AuthorRegistryEntry {
  readonly publicKey: string;
  readonly status: AuthorRegistryStatus;
}

export interface AuthorRegistrySnapshot {
  readonly version: 1;
  readonly campusId: string;
  readonly sequence: number;
  readonly issuedAtEpochMs: number;
  readonly expiresAtEpochMs: number;
  readonly authors: readonly AuthorRegistryEntry[];
  readonly signature: string;
}

export type AuthorRegistrySnapshotWriteResult =
  | "installed"
  | "unchanged"
  | "stale"
  | "conflict";

export interface AuthorRegistrySnapshotStore {
  loadLatest(campusId: string): Promise<unknown | null>;
  saveIfNewer(
    snapshot: AuthorRegistrySnapshot,
    installedAtEpochMs: number
  ): Promise<AuthorRegistrySnapshotWriteResult>;
}

export interface AuthorRegistrySignatureVerifier {
  verify(
    pinnedServerPublicKey: string,
    canonicalMessage: string,
    signature: string
  ): Promise<boolean>;
}

export interface CampusAuthorRegistryOptions {
  readonly campusId: string;
  /** Ed25519 public key pinned by the application, never supplied by the snapshot. */
  readonly pinnedServerPublicKey: string;
  readonly maxSnapshotAgeMs: number;
  readonly signatureVerifier: AuthorRegistrySignatureVerifier;
  readonly store: AuthorRegistrySnapshotStore;
  /** Must be a rollback-aware clock shared with the mesh ingress timestamp source. */
  readonly nowEpochMs: () => number;
  readonly allowedClockSkewMs?: number;
}

const SNAPSHOT_DOMAIN = "VANGUARD_AUTHOR_REGISTRY_V1\n";
const MAX_REGISTRY_AUTHORS = 100_000;
const MAX_SNAPSHOT_CHARACTERS = 8 * 1024 * 1024;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function assertExactKeys(value: Record<string, unknown>, expected: readonly string[]): void {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  if (
    actual.length !== sortedExpected.length ||
    actual.some((key, index) => key !== sortedExpected[index])
  ) {
    throw new TypeError("Author registry snapshot contains missing or unexpected fields");
  }
}

/** Validates the untrusted wire shape without claiming that its signature is valid. */
export function assertAuthorRegistrySnapshot(
  candidate: unknown
): asserts candidate is AuthorRegistrySnapshot {
  if (!isRecord(candidate)) throw new TypeError("Author registry snapshot must be an object");
  assertExactKeys(candidate, [
    "version",
    "campusId",
    "sequence",
    "issuedAtEpochMs",
    "expiresAtEpochMs",
    "authors",
    "signature"
  ]);

  if (candidate.version !== 1) throw new TypeError("Unsupported author registry version");
  if (
    typeof candidate.campusId !== "string" ||
    !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(candidate.campusId)
  ) {
    throw new TypeError("Invalid author registry campus ID");
  }
  if (
    typeof candidate.sequence !== "number" ||
    !Number.isSafeInteger(candidate.sequence) ||
    candidate.sequence < 1
  ) {
    throw new TypeError("Invalid author registry sequence");
  }
  if (
    typeof candidate.issuedAtEpochMs !== "number" ||
    !Number.isSafeInteger(candidate.issuedAtEpochMs) ||
    candidate.issuedAtEpochMs < 0
  ) {
    throw new TypeError("Invalid author registry issue time");
  }
  if (
    typeof candidate.expiresAtEpochMs !== "number" ||
    !Number.isSafeInteger(candidate.expiresAtEpochMs) ||
    candidate.expiresAtEpochMs <= candidate.issuedAtEpochMs
  ) {
    throw new TypeError("Invalid author registry expiry");
  }
  if (!Array.isArray(candidate.authors) || candidate.authors.length > MAX_REGISTRY_AUTHORS) {
    throw new TypeError("Invalid author registry entries");
  }

  let previousPublicKey = "";
  for (const item of candidate.authors) {
    if (!isRecord(item)) throw new TypeError("Author registry entry must be an object");
    assertExactKeys(item, ["publicKey", "status"]);
    if (
      typeof item.publicKey !== "string" ||
      !/^[A-Za-z0-9_-]{59}$/.test(item.publicKey)
    ) {
      throw new TypeError("Invalid author registry public key");
    }
    if (item.status !== "active" && item.status !== "suspended" && item.status !== "revoked") {
      throw new TypeError("Invalid author registry status");
    }
    if (item.publicKey <= previousPublicKey) {
      throw new TypeError("Author registry entries must be uniquely sorted by public key");
    }
    previousPublicKey = item.publicKey;
  }

  if (typeof candidate.signature !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(candidate.signature)) {
    throw new TypeError("Invalid author registry signature encoding");
  }

  const snapshotJson = canonicalizeJson(candidate);
  if (snapshotJson.length > MAX_SNAPSHOT_CHARACTERS) {
    throw new RangeError("Author registry snapshot exceeds the 8 MiB limit");
  }
}

export function canonicalAuthorRegistryMessage(
  snapshot: AuthorRegistrySnapshot
): string {
  return SNAPSHOT_DOMAIN + canonicalizeJson({
    version: snapshot.version,
    campusId: snapshot.campusId,
    sequence: snapshot.sequence,
    issuedAtEpochMs: snapshot.issuedAtEpochMs,
    expiresAtEpochMs: snapshot.expiresAtEpochMs,
    authors: snapshot.authors
  });
}

/**
 * Fail-closed campus author policy backed by server-signed, monotonic snapshots.
 * The caller is responsible for fetching a snapshot from the authenticated
 * gateway and invoking installSnapshot(); this class never trusts network data
 * until the pinned server signature and freshness rules pass.
 */
export class CampusAuthorRegistry {
  private cachedSnapshot: AuthorRegistrySnapshot | null | undefined;
  private snapshotLoad: Promise<AuthorRegistrySnapshot | null> | undefined;
  private snapshotGeneration = 0;
  private installQueue: Promise<void> = Promise.resolve();
  private readonly nowEpochMs: () => number;
  private readonly allowedClockSkewMs: number;
  private readonly options: CampusAuthorRegistryOptions;

  constructor(options: CampusAuthorRegistryOptions) {
    this.options = Object.freeze({ ...options });
    if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(options.campusId)) {
      throw new TypeError("Invalid campus ID");
    }
    if (!/^[A-Za-z0-9_-]{59}$/.test(options.pinnedServerPublicKey)) {
      throw new TypeError("A pinned Ed25519 registry server key is required");
    }
    if (!Number.isSafeInteger(options.maxSnapshotAgeMs) || options.maxSnapshotAgeMs < 1) {
      throw new RangeError("maxSnapshotAgeMs must be a positive safe integer");
    }
    this.allowedClockSkewMs = options.allowedClockSkewMs ?? 5 * 60 * 1000;
    if (!Number.isSafeInteger(this.allowedClockSkewMs) || this.allowedClockSkewMs < 0) {
      throw new RangeError("allowedClockSkewMs must be a non-negative safe integer");
    }
    this.nowEpochMs = options.nowEpochMs;
  }

  /** Installs a verified snapshot, rejecting rollback and same-sequence equivocation. */
  installSnapshot(candidate: unknown): Promise<void> {
    const operation = this.installQueue.then(() => this.installSnapshotInternal(candidate));
    this.installQueue = operation.then(() => undefined, () => undefined);
    return operation;
  }

  async isTrustedAuthor(publicKey: string, nowEpochMs: number): Promise<boolean> {
    if (
      !/^[A-Za-z0-9_-]{59}$/.test(publicKey) ||
      !Number.isSafeInteger(nowEpochMs) ||
      nowEpochMs < 0
    ) {
      return false;
    }

    const clockNow = this.nowEpochMs();
    if (
      !Number.isSafeInteger(clockNow) ||
      clockNow < 0 ||
      Math.abs(clockNow - nowEpochMs) > this.allowedClockSkewMs
    ) {
      return false;
    }

    // Use the later of the ingress timestamp and registry clock. A clock
    // disagreement can only make the freshness decision more restrictive.
    const effectiveNow = Math.max(clockNow, nowEpochMs);
    const snapshot = await this.getVerifiedSnapshot();
    if (!snapshot || !this.isFresh(snapshot, effectiveNow)) return false;

    let low = 0;
    let high = snapshot.authors.length - 1;
    while (low <= high) {
      const middle = low + Math.floor((high - low) / 2);
      const entry = snapshot.authors[middle]!;
      if (entry.publicKey === publicKey) return entry.status === "active";
      if (entry.publicKey < publicKey) low = middle + 1;
      else high = middle - 1;
    }
    return false;
  }

  private async installSnapshotInternal(candidate: unknown): Promise<void> {
    assertAuthorRegistrySnapshot(candidate);
    const snapshot = freezeSnapshot(candidate);
    if (snapshot.campusId !== this.options.campusId) {
      throw new Error("Author registry snapshot belongs to a different campus");
    }

    const now = this.nowEpochMs();
    if (!this.isFresh(snapshot, now)) {
      throw new Error("Author registry snapshot is expired, stale, or from the future");
    }

    const verified = await this.options.signatureVerifier.verify(
      this.options.pinnedServerPublicKey,
      canonicalAuthorRegistryMessage(snapshot),
      snapshot.signature
    );
    if (!verified) throw new Error("Author registry server signature verification failed");

    const result = await this.options.store.saveIfNewer(snapshot, now);
    if (result === "stale") throw new Error("Author registry snapshot rollback rejected");
    if (result === "conflict") {
      throw new Error("Author registry snapshot sequence equivocation rejected");
    }

    this.snapshotGeneration += 1;
    this.cachedSnapshot = snapshot;
    this.snapshotLoad = undefined;
  }

  private async getVerifiedSnapshot(): Promise<AuthorRegistrySnapshot | null> {
    if (this.cachedSnapshot !== undefined) return this.cachedSnapshot;
    if (this.snapshotLoad) return this.snapshotLoad;

    const generation = this.snapshotGeneration;
    const load = this.loadAndVerifyStoredSnapshot();
    this.snapshotLoad = load;
    const snapshot = await load;

    if (generation !== this.snapshotGeneration) {
      return this.getVerifiedSnapshot();
    }
    this.cachedSnapshot = snapshot;
    if (this.snapshotLoad === load) this.snapshotLoad = undefined;
    return snapshot;
  }

  private async loadAndVerifyStoredSnapshot(): Promise<AuthorRegistrySnapshot | null> {
    try {
      const candidate = await this.options.store.loadLatest(this.options.campusId);
      if (candidate === null) return null;
      assertAuthorRegistrySnapshot(candidate);
      const snapshot = freezeSnapshot(candidate);
      if (snapshot.campusId !== this.options.campusId) return null;

      const verified = await this.options.signatureVerifier.verify(
        this.options.pinnedServerPublicKey,
        canonicalAuthorRegistryMessage(snapshot),
        snapshot.signature
      );
      return verified ? snapshot : null;
    } catch {
      // Corrupt, malformed, or unverifiable local state is never trusted.
      return null;
    }
  }

  private isFresh(snapshot: AuthorRegistrySnapshot, nowEpochMs: number): boolean {
    if (!Number.isSafeInteger(nowEpochMs) || nowEpochMs < 0) return false;
    if (\n      snapshot.issuedAtEpochMs > nowEpochMs &&\n      snapshot.issuedAtEpochMs - nowEpochMs > this.allowedClockSkewMs\n    ) return false;
    if (snapshot.expiresAtEpochMs <= nowEpochMs) return false;
    return nowEpochMs - snapshot.issuedAtEpochMs <= this.options.maxSnapshotAgeMs;
  }
}
