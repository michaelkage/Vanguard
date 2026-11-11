import { describe, expect, it } from "vitest";
import vector from "../protocol/test-vectors/v1-basic-message.json";
import { canonicalizeJson } from "../src/protocol/canonical-json";
import {
  canonicalUnsignedEvent,
  eventIdForCanonicalMessage
} from "../src/protocol/event-protocol";

describe("canonicalizeJson", () => {
  it("sorts object keys recursively and preserves array order", () => {
    expect(canonicalizeJson({ z: 1, a: { y: 2, b: 3 }, list: [2, 1] }))
      .toBe('{"a":{"b":3,"y":2},"list":[2,1],"z":1}');
  });

  it("normalizes negative zero according to JSON number serialization", () => {
    expect(canonicalizeJson({ value: -0 })).toBe('{"value":0}');
  });

  it("rejects non-finite numbers", () => {
    expect(() => canonicalizeJson({ value: Number.NaN })).toThrow("finite");
  });

  it("rejects cycles", () => {
    const value: { self?: unknown } = {};
    value.self = value;
    expect(() => canonicalizeJson(value)).toThrow("cycles");
  });

  it("rejects ill-formed unicode", () => {
    expect(() => canonicalizeJson({ value: "\ud800" })).toThrow("unpaired surrogate");
  });
});

describe("protocol v1 cross-language vector", () => {
  it("matches the Kotlin canonical encoder byte-for-byte", () => {
    expect(canonicalUnsignedEvent(
      vector.type,
      vector.authorPublicKey,
      vector.createdAtEpochMs,
      vector.expiresAtEpochMs,
      vector.payloadCanonicalJson
    )).toBe(vector.unsignedCanonicalJson);
  });

  it("derives the same SHA-256 event ID as the Kotlin reference core", async () => {
    expect(await eventIdForCanonicalMessage(vector.unsignedCanonicalJson)).toBe(vector.eventId);
  });

  it("rejects non-canonical payload strings", () => {
    expect(() => canonicalUnsignedEvent(
      "message.created", "A".repeat(59), 1, null, '{"z":1,"a":2}'
    )).toThrow("not canonical");
  });
});
