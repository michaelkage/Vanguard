import type {
  AuthorRegistrySnapshot,
  AuthorRegistrySnapshotStore
} from "../identity/author-registry";
import { canonicalizeJson } from "../protocol/canonical-json";
import {
  loadAuthorRegistrySnapshot,
  saveAuthorRegistrySnapshotIfNewer
} from "./author-registry-repository";

/** SQLCipher-backed persistence for the last accepted campus registry snapshot. */
export const sqliteAuthorRegistrySnapshotStore: AuthorRegistrySnapshotStore = {
  loadLatest: campusId => loadAuthorRegistrySnapshot(campusId),
  saveIfNewer: (snapshot: AuthorRegistrySnapshot, installedAtEpochMs) =>
    saveAuthorRegistrySnapshotIfNewer(
      snapshot.campusId,
      snapshot.sequence,
      canonicalizeJson(snapshot),
      installedAtEpochMs
    )
};
