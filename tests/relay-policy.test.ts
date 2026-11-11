import { describe, expect, it } from "vitest";
import type { SignedEventEnvelope } from "../src/protocol/envelope";
import { evaluateRelay } from "../src/protocol/relay-policy";

const event: SignedEventEnvelope = {
  version: 1,
  id: "A".repeat(43),
  type: "message.created",
  authorPublicKey: "B".repeat(59),
  createdAtEpochMs: 1_000,
  expiresAtEpochMs: 10_000,
  payloadCanonicalJson: "{}",
  signature: "C".repeat(86)
};

describe("evaluateRelay", () => {
  it("allows an unexpired event below its hop limit", () => {
    expect(evaluateRelay(event, { hopCount: 1, maxHops: 5 }, 2_000, false))
      .toEqual({ allowed: true });
  });

  it("rejects an expired event", () => {
    expect(evaluateRelay(event, { hopCount: 0, maxHops: 5 }, 10_000, false))
      .toEqual({ allowed: false, reason: "expired" });
  });

  it("rejects an event at its hop limit", () => {
    expect(evaluateRelay(event, { hopCount: 5, maxHops: 5 }, 2_000, false))
      .toEqual({ allowed: false, reason: "hop_limit" });
  });

  it("rejects a peer that already received the event", () => {
    expect(evaluateRelay(event, { hopCount: 0, maxHops: 5 }, 2_000, true))
      .toEqual({ allowed: false, reason: "already_sent_to_peer" });
  });

  it("rejects invalid or out-of-policy relay metadata", () => {
    expect(evaluateRelay(event, { hopCount: -1, maxHops: 99 }, 2_000, false))
      .toEqual({ allowed: false, reason: "invalid_relay_metadata" });
  });
});
