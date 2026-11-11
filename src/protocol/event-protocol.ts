import * as Crypto from "expo-crypto";
import { assertEnvelopeShape, type SignedEventEnvelope } from "./envelope";
import { canonicalizeJson } from "./canonical-json";

export interface EventSigningProvider {
  getOrCreate(): Promise<{ readonly publicKey: string }>;
  sign(canonicalMessage: string): Promise<string>;
  verify(publicKey: string, canonicalMessage: string, signature: string): Promise<boolean>;
}

export interface CreateEventInput {
  readonly type: string;
  readonly createdAtEpochMs: number;
  readonly expiresAtEpochMs?: number | null;
  readonly payload: Readonly<Record<string, unknown>>;
}

function validateUnsignedFields(
  type: string,
  createdAtEpochMs: number,
  expiresAtEpochMs: number | null
): void {
  if (!/^[a-z][a-z0-9_.-]{0,63}$/.test(type)) throw new TypeError("Invalid event type");
  if (!Number.isSafeInteger(createdAtEpochMs) || createdAtEpochMs < 0) {
    throw new TypeError("Invalid event creation time");
  }
  if (
    expiresAtEpochMs !== null &&
    (!Number.isSafeInteger(expiresAtEpochMs) || expiresAtEpochMs <= createdAtEpochMs)
  ) {
    throw new TypeError("Invalid event expiry");
  }
}

export function canonicalUnsignedEvent(
  type: string,
  authorPublicKey: string,
  createdAtEpochMs: number,
  expiresAtEpochMs: number | null,
  payloadCanonicalJson: string
): string {
  validateUnsignedFields(type, createdAtEpochMs, expiresAtEpochMs);
  if (!authorPublicKey.trim()) throw new TypeError("Invalid author public key");
  const payload = JSON.parse(payloadCanonicalJson) as unknown;
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    throw new TypeError("Event payload must be a JSON object");
  }
  if (canonicalizeJson(payload) !== payloadCanonicalJson) {
    throw new TypeError("Event payload is not canonical JSON");
  }

  return `{"version":1,"type":${JSON.stringify(type)},"authorPublicKey":${JSON.stringify(authorPublicKey)},"createdAtEpochMs":${createdAtEpochMs},"expiresAtEpochMs":${expiresAtEpochMs === null ? "null" : expiresAtEpochMs},"payload":${payloadCanonicalJson}}`;
}

export async function eventIdForCanonicalMessage(value: string): Promise<string> {
  const digest = await Crypto.digestStringAsync(
    Crypto.CryptoDigestAlgorithm.SHA256,
    value,
    { encoding: Crypto.CryptoEncoding.BASE64 }
  );
  return digest.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export async function createSignedEvent(
  input: CreateEventInput,
  signer: EventSigningProvider
): Promise<SignedEventEnvelope> {
  const expiresAtEpochMs = input.expiresAtEpochMs ?? null;
  validateUnsignedFields(input.type, input.createdAtEpochMs, expiresAtEpochMs);
  const payloadCanonicalJson = canonicalizeJson(input.payload);
  if (typeof input.payload !== "object" || input.payload === null || Array.isArray(input.payload)) {
    throw new TypeError("Event payload must be a JSON object");
  }

  const identity = await signer.getOrCreate();
  const canonicalMessage = canonicalUnsignedEvent(
    input.type,
    identity.publicKey,
    input.createdAtEpochMs,
    expiresAtEpochMs,
    payloadCanonicalJson
  );
  const envelope: SignedEventEnvelope = {
    version: 1,
    id: await eventIdForCanonicalMessage(canonicalMessage),
    type: input.type,
    authorPublicKey: identity.publicKey,
    createdAtEpochMs: input.createdAtEpochMs,
    expiresAtEpochMs,
    payloadCanonicalJson,
    signature: await signer.sign(canonicalMessage)
  };
  assertEnvelopeShape(envelope);
  return envelope;
}

export async function verifySignedEvent(
  candidate: unknown,
  signer: EventSigningProvider,
  nowEpochMs?: number
): Promise<boolean> {
  assertEnvelopeShape(candidate);
  const event = candidate;
  if (
    nowEpochMs !== undefined &&
    (!Number.isSafeInteger(nowEpochMs) || nowEpochMs < 0)
  ) {
    throw new RangeError("nowEpochMs must be a non-negative safe integer");
  }
  if (event.expiresAtEpochMs !== null && nowEpochMs !== undefined &&
      nowEpochMs >= event.expiresAtEpochMs) {
    return false;
  }

  const canonicalMessage = canonicalUnsignedEvent(
    event.type,
    event.authorPublicKey,
    event.createdAtEpochMs,
    event.expiresAtEpochMs,
    event.payloadCanonicalJson
  );
  if (await eventIdForCanonicalMessage(canonicalMessage) !== event.id) return false;
  return signer.verify(event.authorPublicKey, canonicalMessage, event.signature);
}
