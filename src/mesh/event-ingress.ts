import {
  assertEnvelopeShape,
  type SignedEventEnvelope
} from "../protocol/envelope";
import {
  EventVerificationError,
  storeVerifiedEvent,
  type SignatureVerifier
} from "../storage/event-repository";
import type { NearbyTransport } from "./transport";

export const MAX_RELAY_PACKET_BYTES = 24 * 1024;
const MAX_PENDING_INGRESS = 64;
const MAX_CONCURRENT_INGRESS = 4;

export interface RelayPacket {
  readonly version: 1;
  readonly envelope: SignedEventEnvelope;
  readonly relay: {
    readonly hopCount: number;
  };
}

export type IngressRejectionReason =
  | "invalid_packet"
  | "signature_or_author_rejected"
  | "storage_rejected"
  | "overloaded";

export interface AuthorTrustPolicy {
  /**
   * Must fail closed for unknown keys, revoked keys, and snapshots whose
   * freshness policy cannot be satisfied. A valid signature alone is not
   * proof of campus enrollment.
   */
  isTrustedAuthor(publicKey: string, nowEpochMs: number): Promise<boolean>;
}

export interface VerifiedIngressOptions {
  readonly signatureVerifier: SignatureVerifier;
  readonly authorTrustPolicy: AuthorTrustPolicy;
  /** Local relay policy; never accepted from an untrusted peer. */
  readonly maxHops?: number;
  readonly nowEpochMs?: () => number;
  readonly onAccepted?: (
    peerDeviceId: string,
    packet: RelayPacket,
    inserted: boolean
  ) => void;
  readonly onRejected?: (
    peerDeviceId: string,
    reason: IngressRejectionReason
  ) => void;
}

interface PendingPacket {
  readonly peerDeviceId: string;
  readonly bytes: Uint8Array;
}

function assertRelayMetadata(value: unknown): asserts value is RelayPacket["relay"] {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError("Relay metadata must be an object");
  }
  const candidate = value as Record<string, unknown>;
  const keys = Object.keys(candidate).sort();
  if (keys.length !== 1 || keys[0] !== "hopCount") {
    throw new TypeError("Relay metadata contains unexpected fields");
  }
  if (
    typeof candidate.hopCount !== "number" ||
    !Number.isSafeInteger(candidate.hopCount) ||
    candidate.hopCount < 1 ||
    candidate.hopCount > 8
  ) {
    throw new TypeError("Relay hop metadata is outside protocol limits");
  }
}

/** Serializes an immutable signed event with separate, mutable relay metadata. */
export function encodeRelayPacket(
  envelope: SignedEventEnvelope,
  relay: RelayPacket["relay"]
): Uint8Array {
  assertEnvelopeShape(envelope);
  assertRelayMetadata(relay);
  const encoded = new TextEncoder().encode(JSON.stringify({
    version: 1,
    envelope,
    relay
  }));
  if (encoded.byteLength === 0 || encoded.byteLength > MAX_RELAY_PACKET_BYTES) {
    throw new RangeError("Relay packet must fit within the 24 KiB transport limit");
  }
  return encoded;
}

/** Parses untrusted transport bytes; cryptographic and author-policy checks happen at ingress. */
export function decodeRelayPacket(bytes: Uint8Array): RelayPacket {
  if (
    !(bytes instanceof Uint8Array) ||
    bytes.byteLength === 0 ||
    bytes.byteLength > MAX_RELAY_PACKET_BYTES
  ) {
    throw new TypeError("Relay packet has an invalid byte length");
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown;
  } catch {
    throw new TypeError("Relay packet is not valid UTF-8 JSON");
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new TypeError("Relay packet must be an object");
  }
  const candidate = parsed as Record<string, unknown>;
  const keys = Object.keys(candidate).sort();
  if (
    keys.length !== 3 ||
    keys[0] !== "envelope" ||
    keys[1] !== "relay" ||
    keys[2] !== "version" ||
    candidate.version !== 1
  ) {
    throw new TypeError("Relay packet has an unsupported or invalid frame");
  }

  assertEnvelopeShape(candidate.envelope);
  assertRelayMetadata(candidate.relay);
  return {
    version: 1,
    envelope: candidate.envelope,
    relay: candidate.relay
  };
}

/**
 * Attaches bounded, fail-closed mesh ingress. An event is persisted only after
 * its Ed25519 signature and the caller-supplied campus key policy both pass.
 * The author key policy must account for offline revocation-snapshot freshness.
 * Hop count is unauthenticated relay metadata: this enforces a local ceiling,
 * not proof of the packet's true route length. A malicious peer can reset it
 * until authenticated relay provenance is implemented.
 */
export function attachVerifiedEventIngress(
  transport: NearbyTransport,
  options: VerifiedIngressOptions
): () => void {
  const now = options.nowEpochMs ?? Date.now;
  const maxHops = options.maxHops ?? 5;
  if (!Number.isSafeInteger(maxHops) || maxHops < 1 || maxHops > 8) {
    throw new RangeError("maxHops must be an integer between 1 and 8");
  }
  const queue: PendingPacket[] = [];
  let active = 0;
  let disposed = false;

  const reportRejected = (
    peerDeviceId: string,
    reason: IngressRejectionReason
  ): void => {
    try {
      options.onRejected?.(peerDeviceId, reason);
    } catch {
      // Application observers must not break the transport worker.
    }
  };

  const process = async (pending: PendingPacket): Promise<void> => {
    let packet: RelayPacket;
    try {
      packet = decodeRelayPacket(pending.bytes);
    } catch {
      reportRejected(pending.peerDeviceId, "invalid_packet");
      return;
    }

    if (packet.relay.hopCount > maxHops) {
      reportRejected(pending.peerDeviceId, "invalid_packet");
      return;
    }

    const receivedAt = now();
    if (!Number.isSafeInteger(receivedAt) || receivedAt < 0) {
      reportRejected(pending.peerDeviceId, "storage_rejected");
      return;
    }

    const verifier: SignatureVerifier = {
      verify: async envelope => {
        if (disposed || !(await options.signatureVerifier.verify(envelope))) return false;
        const trusted = await options.authorTrustPolicy.isTrustedAuthor(
          envelope.authorPublicKey,
          receivedAt
        );
        return !disposed && trusted;
      }
    };

    try {
      const inserted = await storeVerifiedEvent(packet.envelope, verifier, {
        nowEpochMs: receivedAt,
        receivedHopCount: packet.relay.hopCount,
        maxHops,
        receivedFromPeerId: pending.peerDeviceId
      });
      if (!disposed) {
        try {
          options.onAccepted?.(pending.peerDeviceId, packet, inserted);
        } catch {
          // Observer failures cannot roll back a successfully committed event.
        }
      }
    } catch (error) {
      if (disposed) return;
      reportRejected(
        pending.peerDeviceId,
        error instanceof EventVerificationError
          ? "signature_or_author_rejected"
          : "storage_rejected"
      );
    }
  };

  const pump = (): void => {
    while (!disposed && active < MAX_CONCURRENT_INGRESS && queue.length > 0) {
      const pending = queue.shift();
      if (!pending) return;
      active += 1;
      void process(pending).finally(() => {
        active -= 1;
        pump();
      });
    }
  };

  const unsubscribe = transport.addPayloadListener((peerDeviceId, bytes) => {
    if (disposed) return;
    if (!peerDeviceId || queue.length >= MAX_PENDING_INGRESS) {
      reportRejected(peerDeviceId, "overloaded");
      return;
    }
    queue.push({ peerDeviceId, bytes: new Uint8Array(bytes) });
    pump();
  });

  return () => {
    if (disposed) return;
    disposed = true;
    queue.length = 0;
    unsubscribe();
  };
}
