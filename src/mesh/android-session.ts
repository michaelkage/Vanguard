import { AndroidNearbyTransport } from "./transport";
import type { NearbyMeshSession } from "./session";
import { NearbyMeshSession as MeshSession } from "./session";
import type { MeshSessionCallbacks } from "./session";
import type { AuthorTrustPolicy } from "./event-ingress";
import { nativeEventSignatureVerifier } from "./native-event-verifier";
import {
  createNativeCampusAuthorRegistry
} from "../identity/native-author-registry";
import type { CampusAuthorRegistry } from "../identity/author-registry";

export interface AndroidNearbyMeshSessionOptions extends MeshSessionCallbacks {
  readonly serviceId: string;
  readonly endpointName: string;
  /** Must fail closed for unknown/revoked keys and stale revocation snapshots. */
  readonly authorTrustPolicy: AuthorTrustPolicy;
  readonly maxHops?: number;
  readonly nowEpochMs?: () => number;
}

export interface AndroidNearbyMeshSessionHandle {
  readonly session: NearbyMeshSession;
  readonly transport: AndroidNearbyTransport;
  /** Stops the session and releases the native event subscriptions. */
  dispose(): Promise<void>;
}

export interface AndroidCampusMeshSessionOptions extends MeshSessionCallbacks {
  readonly serviceId: string;
  readonly endpointName: string;
  readonly campusId: string;
  /** Pinned in application configuration; never obtained from the remote snapshot. */
  readonly pinnedRegistryServerPublicKey: string;
  readonly maxRegistrySnapshotAgeMs: number;
  /** A rollback-aware clock shared by registry freshness and event ingress. */
  readonly nowEpochMs: () => number;
  readonly maxHops?: number;
}

export interface AndroidCampusMeshSessionHandle extends AndroidNearbyMeshSessionHandle {
  readonly authorRegistry: CampusAuthorRegistry;
}

/**
 * Production Android composition root. The generic factory still requires an
 * explicit trust policy; it never invents or defaults to trusting authors.
 */
export function createAndroidNearbyMeshSession(
  options: AndroidNearbyMeshSessionOptions
): AndroidNearbyMeshSessionHandle {
  const transport = new AndroidNearbyTransport();
  let session: NearbyMeshSession;
  try {
    session = new MeshSession({
      ...options,
      transport,
      signatureVerifier: nativeEventSignatureVerifier
    });
  } catch (error) {
    transport.dispose();
    throw error;
  }

  return {
    session,
    transport,
    async dispose() {
      try {
        await session.stop();
      } finally {
        transport.dispose();
      }
    }
  };
}

/**
 * Composes native event verification, pinned-server campus trust, and the
 * SQLCipher snapshot cache. The caller must install a signed registry snapshot
 * obtained from the authenticated backend before any author will be trusted.
 */
export function createAndroidCampusMeshSession(
  options: AndroidCampusMeshSessionOptions
): AndroidCampusMeshSessionHandle {
  const {
    campusId,
    pinnedRegistryServerPublicKey,
    maxRegistrySnapshotAgeMs,
    ...sessionOptions
  } = options;
  const authorRegistry = createNativeCampusAuthorRegistry({
    campusId,
    pinnedServerPublicKey: pinnedRegistryServerPublicKey,
    maxSnapshotAgeMs: maxRegistrySnapshotAgeMs,
    nowEpochMs: sessionOptions.nowEpochMs
  });
  const session = createAndroidNearbyMeshSession({
    ...sessionOptions,
    authorTrustPolicy: authorRegistry
  });

  return {
    ...session,
    authorRegistry
  };
}
