import { VanguardIdentity } from "../../modules/vanguard-identity/src";
import type { EventSigningProvider } from "../protocol/event-protocol";

export const nativeEventSigner: EventSigningProvider = {
  getOrCreate: async () => VanguardIdentity.getOrCreate(),
  sign: canonicalMessage => VanguardIdentity.sign(canonicalMessage),
  verify: (publicKey, canonicalMessage, signature) =>
    VanguardIdentity.verify(publicKey, canonicalMessage, signature)
};
