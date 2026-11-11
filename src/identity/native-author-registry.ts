import { VanguardIdentity } from "../../modules/vanguard-identity/src";
import {
  CampusAuthorRegistry,
  type AuthorRegistrySnapshotStore,
  type CampusAuthorRegistryOptions
} from "./author-registry";
import { sqliteAuthorRegistrySnapshotStore } from "../storage/sqlite-author-registry-store";

export type NativeCampusAuthorRegistryOptions = Omit<
  CampusAuthorRegistryOptions,
  "signatureVerifier" | "store"
> & {
  readonly store?: AuthorRegistrySnapshotStore;
};

/**
 * Production Android composition: verifies the server's Ed25519 snapshot
 * signature with the native verifier and persists accepted snapshots in the
 * SQLCipher-backed local store. The server public key must be pinned by the
 * application configuration and supplied explicitly.
 */
export function createNativeCampusAuthorRegistry(
  options: NativeCampusAuthorRegistryOptions
): CampusAuthorRegistry {
  return new CampusAuthorRegistry({
    ...options,
    signatureVerifier: {
      verify: (publicKey, message, signature) =>
        VanguardIdentity.verify(publicKey, message, signature)
    },
    store: options.store ?? sqliteAuthorRegistrySnapshotStore
  });
}
