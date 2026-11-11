/**
 * RFC 8785-style JSON canonicalization for the JSON data model used by Vanguard.
 * Object keys are sorted by UTF-16 code units and numbers use ECMAScript JSON
 * serialization. Non-JSON values, cycles, and ill-formed Unicode are rejected.
 */
export function canonicalizeJson(value: unknown): string {
  const ancestors = new Set<object>();

  function assertUnicode(input: string): void {
    for (let i = 0; i < input.length; i += 1) {
      const code = input.charCodeAt(i);
      if (code >= 0xd800 && code <= 0xdbff) {
        const next = input.charCodeAt(i + 1);
        if (!(next >= 0xdc00 && next <= 0xdfff)) {
          throw new TypeError("Canonical JSON cannot contain an unpaired surrogate");
        }
        i += 1;
      } else if (code >= 0xdc00 && code <= 0xdfff) {
        throw new TypeError("Canonical JSON cannot contain an unpaired surrogate");
      }
    }
  }

  function encode(input: unknown, depth: number): string {
    if (depth > 64) throw new RangeError("Canonical JSON nesting exceeds 64 levels");
    if (input === null) return "null";
    if (typeof input === "boolean") return input ? "true" : "false";
    if (typeof input === "string") {
      assertUnicode(input);
      return JSON.stringify(input);
    }
    if (typeof input === "number") {
      if (!Number.isFinite(input)) throw new TypeError("Canonical JSON numbers must be finite");
      return JSON.stringify(input);
    }
    if (typeof input !== "object") {
      throw new TypeError("Value is not representable in canonical JSON");
    }

    if (ancestors.has(input)) throw new TypeError("Canonical JSON cannot contain cycles");
    ancestors.add(input);
    try {
      if (Array.isArray(input)) {
        const values: string[] = [];
        for (let index = 0; index < input.length; index += 1) {
          if (!(index in input)) throw new TypeError("Canonical JSON arrays cannot contain holes");
          values.push(encode(input[index], depth + 1));
        }
        return `[${values.join(",")}]`;
      }

      const prototype = Object.getPrototypeOf(input);
      if (prototype !== Object.prototype && prototype !== null) {
        throw new TypeError("Canonical JSON objects must be plain objects");
      }
      if (Object.getOwnPropertySymbols(input).length > 0) {
        throw new TypeError("Canonical JSON objects cannot contain symbol keys");
      }

      const record = input as Record<string, unknown>;
      const keys = Object.keys(record).sort();
      const fields = keys.map(key => {
        assertUnicode(key);
        return `${JSON.stringify(key)}:${encode(record[key], depth + 1)}`;
      });
      return `{${fields.join(",")}}`;
    } finally {
      ancestors.delete(input);
    }
  }

  return encode(value, 0);
}
