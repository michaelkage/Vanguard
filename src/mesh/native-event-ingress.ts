import type { NearbyTransport } from "./transport";
import {
  attachVerifiedEventIngress,
  type AuthorTrustPolicy,
  type VerifiedIngressOptions
} from "./event-ingress";
import { nativeEventSignatureVerifier } from "./native-event-verifier";

export type NativeVerifiedIngressOptions = Omit<
  VerifiedIngressOptions,
  "signatureVerifier" | "authorTrustPolicy"
> & {
  readonly authorTrustPolicy: AuthorTrustPolicy;
};

/** Attaches Nearby ingress using the device's native Ed25519 verifier. */
export function attachNativeVerifiedEventIngress(
  transport: NearbyTransport,
  options: NativeVerifiedIngressOptions
): () => void {
  return attachVerifiedEventIngress(transport, {
    ...options,
    signatureVerifier: nativeEventSignatureVerifier
  });
}
