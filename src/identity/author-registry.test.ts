import { describe, expect, it, vi } from "vitest";
import { canonicalizeJson } from "../protocol/canonical-json";
import {
  assertAuthorRegistrySnapshot,
  CampusAuthorRegistry,
  type AuthorRegistrySnapshot,
  type AuthorRegistrySnapshotStore
} from "./author-registry";

const activeKey = "A".repeat(59);
const suspendedKey = "B".repeat(59);
const revokedKey = "C".repeat(59);
const serverKey = "Z".repeat(59);

function makeSnapshot(
  overrides: Partial<AuthorRegistrySnapshot> = {}
): AuthorRegistrySnapshot {
  return {
    version: 1,
    campusId: "unilag",
    sequence: 1,
    issuedAtEpochMs: 1_000,
    expiresAtEpochMs: 100_000,
    authors: [
      { publicKey: activeKey, status: "active" },
      { publicKey: suspendedKey, status: "suspended" },
      { publicKey: revokedKey, status: "revoked" }
    ],
    signature: "S".repeat(86),
    ...overrides
  };
}

function createStore(initial: AuthorRegistrySnapshot | null = null) {
  let latest: AuthorRegistrySnapshot | null = initial;
  const store: AuthorRegistrySnapshotStore = {
    loadLatest: vi.fn(async campusId =>
      latest?.campusId === campusId ? latest : null
    ),
    saveIfNewer: vi.fn(async (snapshot: AuthorRegistrySnapshot, _installedAtEpochMs: number) => {
      if (latest === null) {
        latest = snapshot;
        return "installed" as const;
      }
      if (snapshot.sequence < latest.sequence) return "stale" as const;
      if (snapshot.sequence === latest.sequence) {
        return canonicalizeJson(snapshot) === canonicalizeJson(latest)
          ? "unchanged" as const
          : "conflict" as const;
      }
      latest = snapshot;
      return "installed" as const;
    })
  };
  return {
    store,
    get latest() {
      return latest;
    }
  };
}

function createRegistry(
  store: AuthorRegistrySnapshotStore,
  options: {
    now?: () => number;
    maxAge?: number;
    verify?: (publicKey: string, message: string, signature: string) => Promise<boolean>;
  } = {}
) {
  const verify = options.verify ?? vi.fn().mockResolvedValue(true);
  const registry = new CampusAuthorRegistry({
    campusId: "unilag",
    pinnedServerPublicKey: serverKey,
    maxSnapshotAgeMs: options.maxAge ?? 10_000,
    signatureVerifier: { verify },
    store,
    nowEpochMs: options.now ?? (() => 2_000)
  });
  return { registry, verify };
}

describe("CampusAuthorRegistry", () => {
  it("trusts only active keys in a fresh, server-signed campus snapshot", async () => {
    const memory = createStore();
    const { registry, verify } = createRegistry(memory.store);

    await registry.installSnapshot(makeSnapshot());

    expect(verify).toHaveBeenCalledOnce();
    expect(await registry.isTrustedAuthor(activeKey, 2_000)).toBe(true);
    expect(await registry.isTrustedAuthor(suspendedKey, 2_000)).toBe(false);
    expect(await registry.isTrustedAuthor(revokedKey, 2_000)).toBe(false);
    expect(await registry.isTrustedAuthor("D".repeat(59), 2_000)).toBe(false);
  });

  it("fails closed when the pinned server signature is invalid", async () => {
    const memory = createStore();
    const { registry, verify } = createRegistry(memory.store, {
      verify: vi.fn().mockResolvedValue(false)
    });

    await expect(registry.installSnapshot(makeSnapshot())).rejects.toThrow(
      "server signature verification failed"
    );
    expect(memory.latest).toBeNull();
    expect(verify).not.toHaveBeenCalled();
    expect(await registry.isTrustedAuthor(activeKey, 2_000)).toBe(false);
  });

  it("rejects snapshots for another campus before persistence", async () => {
    const memory = createStore();
    const { registry, verify } = createRegistry(memory.store);

    await expect(
      registry.installSnapshot(makeSnapshot({ campusId: "other-campus" }))
    ).rejects.toThrow("different campus");
    expect(verify).not.toHaveBeenCalled();
    expect(memory.latest).toBeNull();
  });

  it("rejects expired, stale, and future-issued snapshots", async () => {
    const memory = createStore();
    const { registry, verify } = createRegistry(memory.store, {
      now: () => 20_000,
      maxAge: 5_000
    });

    await expect(
      registry.installSnapshot(makeSnapshot({ expiresAtEpochMs: 19_999 }))
    ).rejects.toThrow("expired, stale, or from the future");
    await expect(
      registry.installSnapshot(makeSnapshot({ issuedAtEpochMs: 1_000, expiresAtEpochMs: 100_000 }))
    ).rejects.toThrow("expired, stale, or from the future");
    await expect(
      registry.installSnapshot(makeSnapshot({ issuedAtEpochMs: 30_000, expiresAtEpochMs: 40_000 }))
    ).rejects.toThrow("expired, stale, or from the future");
    expect(verify).not.toHaveBeenCalled();
    expect(memory.latest).toBeNull();
  });

  it("rejects sequence rollback and same-sequence equivocation", async () => {
    const memory = createStore();
    const { registry } = createRegistry(memory.store);
    const first = makeSnapshot();
    const second = makeSnapshot({
      sequence: 2,
      issuedAtEpochMs: 1_500,
      expiresAtEpochMs: 100_000
    });

    await registry.installSnapshot(first);
    await registry.installSnapshot(second);

    await expect(registry.installSnapshot(first)).rejects.toThrow("rollback rejected");
    await expect(registry.installSnapshot(makeSnapshot({
      sequence: 2,
      issuedAtEpochMs: 1_500,
      expiresAtEpochMs: 100_000,
      authors: [{ publicKey: activeKey, status: "revoked" }]
    }))).rejects.toThrow("equivocation rejected");

    expect(memory.latest?.sequence).toBe(2);
    expect(memory.latest?.authors[0]?.status).toBe("active");
  });

  it("re-verifies a persisted snapshot before trusting it after restart", async () => {
    const memory = createStore(makeSnapshot());
    const { registry, verify } = createRegistry(memory.store);

    expect(await registry.isTrustedAuthor(activeKey, 2_000)).toBe(true);
    expect(verify).toHaveBeenCalledOnce();
    expect(memory.store.loadLatest).toHaveBeenCalledWith("unilag");
  });

  it("rejects a tampered persisted snapshot even if its shape is valid", async () => {
    const tampered = makeSnapshot({
      authors: [{ publicKey: activeKey, status: "revoked" }]
    });
    const memory = createStore(tampered);
    const { registry } = createRegistry(memory.store, {
      verify: vi.fn().mockResolvedValue(false)
    });

    expect(await registry.isTrustedAuthor(activeKey, 2_000)).toBe(false);
  });

  it("stops trusting a cached snapshot once its maximum age is exceeded", async () => {
    const memory = createStore();
    let now = 2_000;
    const { registry } = createRegistry(memory.store, {
      now: () => now,
      maxAge: 1_000
    });

    await registry.installSnapshot(makeSnapshot());
    expect(await registry.isTrustedAuthor(activeKey, now)).toBe(true);

    now = 2_001;
    expect(await registry.isTrustedAuthor(activeKey, now)).toBe(false);
  });

  it("requires strictly sorted unique registry entries", () => {
    expect(() => assertAuthorRegistrySnapshot(makeSnapshot({
      authors: [
        { publicKey: suspendedKey, status: "active" },
        { publicKey: activeKey, status: "active" }
      ]
    }))).toThrow("uniquely sorted");

    expect(() => assertAuthorRegistrySnapshot(makeSnapshot({
      authors: [
        { publicKey: activeKey, status: "active" },
        { publicKey: activeKey, status: "revoked" }
      ]
    }))).toThrow("uniquely sorted");
  });
});
