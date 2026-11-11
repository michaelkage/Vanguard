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

/**
 * Validates the transport representation only. It does not verify signatures,
 * establish campus membership, or prove that payload JSON is canonical.
 */
export function assertEnvelopeShape(value: unknown): asserts value is SignedEventEnvelope {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError("Event envelope must be an object");
  }

  const candidate = value as Record<string, unknown>;
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
    !/^[A-Za-z0-9_-]{32,128}$/.test(candidate.authorPublicKey)
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
    new TextEncoder().encode(candidate.payloadCanonicalJson).byteLength > MAX_PAYLOAD_BYTES
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

  if (typeof candidate.signature !== "string" || !/^[A-Za-z0-9_-]{80,100}$/.test(candidate.signature)) {
    throw new TypeError("Invalid signature encoding");
  }

  const envelopeBytes = new TextEncoder().encode(JSON.stringify(candidate)).byteLength;
  if (envelopeBytes > MAX_ENVELOPE_BYTES) {
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
