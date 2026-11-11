import { AndroidNearbyTransport } from "./transport";
import type { NearbyMeshSession } from "./session";
import { NearbyMeshSession as MeshSession } from "./session";
import type { MeshSessionCallbacks } from "./session";
import type { AuthorTrustPolicy } from "./event-ingress";
import { nativeEventSignatureVerifier } from "./native-event-verifier";

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

/**
 * Production Android composition root. The author trust policy remains a
 * mandatory dependency; Vanguard does not yet ship a campus enrollment and
 * revocation registry, so this factory intentionally cannot invent trust.
 */
export function createAndroidNearbyMeshSession(
  options: AndroidNearbyMeshSessionOptions
): AndroidNearbyMeshSessionHandle {
  const transport = new AndroidNearbyTransport();
  const session = new MeshSession({
    ...options,
    transport,
    signatureVerifier: nativeEventSignatureVerifier
  });

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
