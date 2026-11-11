import { VanguardIdentity } from "../../modules/vanguard-identity/src";
import {
  verifySignedEvent,
  type EventSigningProvider
} from "../protocol/event-protocol";
import type { SignatureVerifier } from "../storage/event-repository";

const nativeSigningProvider: EventSigningProvider = {
  getOrCreate: async () => ({
    publicKey: (await VanguardIdentity.getOrCreate()).publicKey
  }),
  sign: canonicalMessage => VanguardIdentity.sign(canonicalMessage),
  verify: (publicKey, canonicalMessage, signature) =>
    VanguardIdentity.verify(publicKey, canonicalMessage, signature)
};

/**
 * Production Android verifier: recomputes the canonical v1 message and event
 * ID in TypeScript, then delegates Ed25519 verification to the native module.
 */
export const nativeEventSignatureVerifier: SignatureVerifier = {
  verify: envelope => verifySignedEvent(envelope, nativeSigningProvider)
};
