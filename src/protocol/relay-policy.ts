import type { RelayMetadata, SignedEventEnvelope } from "./envelope";

export const LOCAL_MAX_HOPS = 8;

export type RelayDecision =
  | { readonly allowed: true }
  | {
      readonly allowed: false;
      readonly reason: "expired" | "hop_limit" | "invalid_relay_metadata" | "already_sent_to_peer";
    };

export function evaluateRelay(
  event: SignedEventEnvelope,
  relay: RelayMetadata,
  nowEpochMs: number,
  alreadySentToPeer: boolean
): RelayDecision {
  if (
    !Number.isSafeInteger(relay.hopCount) ||
    !Number.isSafeInteger(relay.maxHops) ||
    relay.hopCount < 0 ||
    relay.maxHops < 1 ||
    relay.maxHops > LOCAL_MAX_HOPS
  ) {
    return { allowed: false, reason: "invalid_relay_metadata" };
  }

  if (event.expiresAtEpochMs !== null && event.expiresAtEpochMs <= nowEpochMs) {
    return { allowed: false, reason: "expired" };
  }

  if (alreadySentToPeer) {
    return { allowed: false, reason: "already_sent_to_peer" };
  }

  if (relay.hopCount >= relay.maxHops) {
    return { allowed: false, reason: "hop_limit" };
  }

  return { allowed: true };
}
