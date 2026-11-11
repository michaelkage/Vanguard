export const PROTOCOL_VERSION = 1 as const;
export const MAX_ENVELOPE_BYTES = 24 * 1024;
export const MAX_PAYLOAD_BYTES = 16 * 1024;

export interface SignedEventEnvelope {
  readonly version: typeof PROTOCOL_VERSION;
  readonly id: string;
  readonly type: string;
  readonly authorPublicKey: string;
  readonly createdAtEpochMs: number;
  readonly expiresAtEpochMs: number | null;
  readonly payloadCanonicalJson: string;
  readonly signature: string;
}

function utf8ByteLength(value: string): number {
  let bytes = 0;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x7f) bytes += 1;
    else if (code <= 0x7ff) bytes += 2;
    else if (code >= 0xd800 && code <= 0xdbff && index + 1 < value.length) {
      const next = value.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        bytes += 4;
        index += 1;
      } else {
        bytes += 3;
      }
    } else {
      bytes += 3;
    }
  }
  return bytes;
}

/**
 * Validates the transport representation only. It does not verify signatures,
 * establish campus membership, or prove that payload JSON is canonical.
 */
export function assertEnvelopeShape(value: unknown): asserts value is SignedEventEnvelope {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError("Event envelope must be an object");
  }

  const candidate = value as Record<string, unknown>;
  const expectedKeys = [
    "authorPublicKey",
    "createdAtEpochMs",
    "expiresAtEpochMs",
    "id",
    "payloadCanonicalJson",
    "signature",
    "type",
    "version"
  ];
  const actualKeys = Object.keys(candidate).sort();
  if (
    actualKeys.length !== expectedKeys.length ||
    actualKeys.some((key, index) => key !== expectedKeys[index])
  ) {
    throw new TypeError("Event envelope contains missing or unexpected fields");
  }

  if (candidate.version !== PROTOCOL_VERSION) {
    throw new TypeError("Unsupported protocol version");
  }
  if (typeof candidate.id !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(candidate.id)) {
    throw new TypeError("Invalid event ID");
  }
  if (typeof candidate.type !== "string" || !/^[a-z][a-z0-9_.-]{0,63}$/.test(candidate.type)) {
    throw new TypeError("Invalid event type");
  }
  if (
    typeof candidate.authorPublicKey !== "string" ||
    !/^[A-Za-z0-9_-]{59}$/.test(candidate.authorPublicKey)
  ) {
    throw new TypeError("Invalid author public key encoding");
  }
  if (
    typeof candidate.createdAtEpochMs !== "number" ||
    !Number.isSafeInteger(candidate.createdAtEpochMs) ||
    candidate.createdAtEpochMs < 0
  ) {
    throw new TypeError("Invalid event creation time");
  }
  if (
    candidate.expiresAtEpochMs !== null &&
    (
      typeof candidate.expiresAtEpochMs !== "number" ||
      !Number.isSafeInteger(candidate.expiresAtEpochMs) ||
      candidate.expiresAtEpochMs <= candidate.createdAtEpochMs
    )
  ) {
    throw new TypeError("Invalid event expiry");
  }
  if (
    typeof candidate.payloadCanonicalJson !== "string" ||
    utf8ByteLength(candidate.payloadCanonicalJson) > MAX_PAYLOAD_BYTES
  ) {
    throw new TypeError("Invalid or oversized event payload");
  }

  let payload: unknown;
  try {
    payload = JSON.parse(candidate.payloadCanonicalJson);
  } catch {
    throw new TypeError("Event payload is not valid JSON");
  }
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    throw new TypeError("Event payload must be a JSON object");
  }

  if (typeof candidate.signature !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(candidate.signature)) {
    throw new TypeError("Invalid signature encoding");
  }

  if (utf8ByteLength(JSON.stringify(candidate)) > MAX_ENVELOPE_BYTES) {
    throw new TypeError("Event envelope exceeds the transport size limit");
  }
}

export interface RelayMetadata {
  /** Mutable, unauthenticated forwarding metadata; never part of the signed envelope. */
  readonly hopCount: number;
  readonly maxHops: number;
}

export interface RelayCandidate {
  readonly envelope: SignedEventEnvelope;
  readonly relay: RelayMetadata;
}
