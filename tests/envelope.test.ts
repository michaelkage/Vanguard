import { describe, expect, it } from "vitest";
import { assertEnvelopeShape, type SignedEventEnvelope } from "../src/protocol/envelope";

const validEnvelope: SignedEventEnvelope = {
  version: 1,
  id: "A".repeat(43),
  type: "message.created",
  authorPublicKey: "B".repeat(59),
  createdAtEpochMs: 1_000,
  expiresAtEpochMs: 10_000,
  payloadCanonicalJson: "{\"body\":\"hello\"}",
  signature: "C".repeat(86)
};

describe("assertEnvelopeShape", () => {
  it("accepts a correctly shaped v1 event envelope", () => {
    expect(() => assertEnvelopeShape(validEnvelope)).not.toThrow();
  });

  it("rejects unsupported protocol versions", () => {
    expect(() => assertEnvelopeShape({ ...validEnvelope, version: 2 }))
      .toThrow("Unsupported protocol version");
  });

  it("rejects extra fields outside the signed envelope contract", () => {
    expect(() => assertEnvelopeShape({ ...validEnvelope, hopCount: 1 }))
      .toThrow("missing or unexpected fields");
  });

  it("rejects non-object payloads", () => {
    expect(() => assertEnvelopeShape({ ...validEnvelope, payloadCanonicalJson: "[]" }))
      .toThrow("JSON object");
  });

  it("rejects expired-at-creation timestamps", () => {
    expect(() => assertEnvelopeShape({
      ...validEnvelope,
      expiresAtEpochMs: validEnvelope.createdAtEpochMs
    })).toThrow("Invalid event expiry");
  });

  it("rejects malformed signature encodings", () => {
    expect(() => assertEnvelopeShape({ ...validEnvelope, signature: "not-a-signature" }))
      .toThrow("Invalid signature encoding");
  });
});
