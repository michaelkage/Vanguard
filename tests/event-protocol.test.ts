import { describe, expect, it } from "vitest";
import { canonicalizeJson } from "../src/protocol/canonical-json";
import { canonicalUnsignedEvent } from "../src/protocol/event-protocol";

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

describe("canonicalUnsignedEvent", () => {
  it("matches the fixed v1 field order used by the Kotlin codec", () => {
    expect(canonicalUnsignedEvent(
      "message.created",
      "A".repeat(59),
      1700000000000,
      null,
      '{"body":"hello","to":"recipient"}'
    )).toBe(
      '{"version":1,"type":"message.created","authorPublicKey":"' +
      "A".repeat(59) +
      '","createdAtEpochMs":1700000000000,"expiresAtEpochMs":null,"payload":{"body":"hello","to":"recipient"}}'
    );
  });

  it("rejects non-canonical payload strings", () => {
    expect(() => canonicalUnsignedEvent(
      "message.created", "A".repeat(59), 1, null, '{"z":1,"a":2}'
    )).toThrow("not canonical");
  });
});
