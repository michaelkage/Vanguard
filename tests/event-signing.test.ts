import { describe, expect, it } from "vitest";
import {
  createSignedEvent,
  verifySignedEvent,
  type EventSigningProvider
} from "../src/protocol/event-protocol";

function createTestSigner(): EventSigningProvider {
  return {
    getOrCreate: async () => ({ publicKey: "A".repeat(59) }),
    sign: async message => {
      if (!message.includes('"version":1')) throw new Error("Unexpected signing input");
      return "B".repeat(86);
    },
    verify: async (publicKey, message, signature) =>
      publicKey === "A".repeat(59) &&
      message.includes('"payload":{"body":"hello","to":"peer"}') &&
      signature === "B".repeat(86)
  };
}

describe("signed event lifecycle", () => {
  it("creates a canonical, content-addressed v1 envelope", async () => {
    const event = await createSignedEvent({
      type: "message.created",
      createdAtEpochMs: 1_700_000_000_000,
      payload: { to: "peer", body: "hello" }
    }, createTestSigner());

    expect(event.id).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(event.payloadCanonicalJson).toBe('{"body":"hello","to":"peer"}');
    expect(event.signature).toBe("B".repeat(86));
    expect(await verifySignedEvent(event, createTestSigner(), 1_700_000_000_001)).toBe(true);
  });

  it("rejects a content-address mismatch before signature verification", async () => {
    const event = await createSignedEvent({
      type: "message.created",
      createdAtEpochMs: 100,
      payload: { body: "hello", to: "peer" }
    }, createTestSigner());

    expect(await verifySignedEvent({ ...event, id: "C".repeat(43) }, createTestSigner())).toBe(false);
  });

  it("rejects expired events", async () => {
    const event = await createSignedEvent({
      type: "message.created",
      createdAtEpochMs: 100,
      expiresAtEpochMs: 200,
      payload: { body: "hello", to: "peer" }
    }, createTestSigner());

    expect(await verifySignedEvent(event, createTestSigner(), 200)).toBe(false);
  });
});
