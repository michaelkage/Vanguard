import { beforeEach, describe, expect, it, vi } from "vitest";
import type { NearbyTransport } from "./transport";
import {
  attachVerifiedEventIngress,
  decodeRelayPacket,
  encodeRelayPacket
} from "./event-ingress";
import { storeVerifiedEvent } from "../storage/event-repository";
import type { SignedEventEnvelope } from "../protocol/envelope";

vi.mock("../storage/event-repository", () => ({
  EventVerificationError: class EventVerificationError extends Error {},
  storeVerifiedEvent: vi.fn()
}));

const envelope: SignedEventEnvelope = {
  version: 1,
  id: "A".repeat(43),
  type: "message",
  authorPublicKey: "B".repeat(59),
  createdAtEpochMs: 1_800_000_000_000,
  expiresAtEpochMs: null,
  payloadCanonicalJson: "{\"body\":\"hello\"}",
  signature: "C".repeat(86)
};

function createTransportHarness(): {
  readonly transport: NearbyTransport;
  emit(peerDeviceId: string, bytes: Uint8Array): void;
  readonly isDetached: () => boolean;
} {
  let listener: ((peerDeviceId: string, payload: Uint8Array) => void) | undefined;
  let detached = false;
  const transport = {
    addPayloadListener(callback: (peerDeviceId: string, payload: Uint8Array) => void) {
      listener = callback;
      return () => {
        detached = true;
        listener = undefined;
      };
    }
  } as unknown as NearbyTransport;

  return {
    transport,
    emit(peerDeviceId, bytes) {
      listener?.(peerDeviceId, bytes);
    },
    isDetached: () => detached
  };
}

describe("relay packet framing", () => {
  it("round-trips an immutable envelope and separate relay metadata", () => {
    const packet = decodeRelayPacket(encodeRelayPacket(envelope, {
      hopCount: 2,
      maxHops: 5
    }));

    expect(packet).toEqual({
      version: 1,
      envelope,
      relay: { hopCount: 2, maxHops: 5 }
    });
  });

  it("rejects relay metadata outside the protocol hop limit", () => {
    expect(() => encodeRelayPacket(envelope, {
      hopCount: 6,
      maxHops: 5
    })).toThrow("Relay hop metadata");
  });

  it("rejects malformed and oversized transport frames", () => {
    expect(() => decodeRelayPacket(new TextEncoder().encode("{"))).toThrow(
      "Relay packet is not valid UTF-8 JSON"
    );
    expect(() => decodeRelayPacket(new Uint8Array(24 * 1024 + 1))).toThrow(
      "Relay packet has an invalid byte length"
    );
  });
});

describe("verified event ingress", () => {
  beforeEach(() => {
    vi.mocked(storeVerifiedEvent).mockReset();
    vi.mocked(storeVerifiedEvent).mockResolvedValue(true);
  });

  it("requires both signature verification and author trust before storage", async () => {
    const harness = createTransportHarness();
    const signatureVerifier = { verify: vi.fn().mockResolvedValue(true) };
    const authorTrustPolicy = { isTrustedAuthor: vi.fn().mockResolvedValue(true) };
    const onAccepted = vi.fn();
    const stop = attachVerifiedEventIngress(harness.transport, {
      signatureVerifier,
      authorTrustPolicy,
      nowEpochMs: () => 1_800_000_000_001,
      onAccepted
    });

    harness.emit("peer-a", encodeRelayPacket(envelope, {
      hopCount: 1,
      maxHops: 5
    }));

    await vi.waitFor(() => {
      expect(storeVerifiedEvent).toHaveBeenCalledOnce();
    });

    const [storedEnvelope, verifier, storageOptions] =
      vi.mocked(storeVerifiedEvent).mock.calls[0]!;
    expect(storedEnvelope).toEqual(envelope);
    expect(storageOptions).toMatchObject({
      nowEpochMs: 1_800_000_000_001,
      receivedHopCount: 1,
      maxHops: 5,
      receivedFromPeerId: "peer-a"
    });
    await expect(verifier.verify(envelope)).resolves.toBe(true);
    expect(signatureVerifier.verify).toHaveBeenCalledWith(envelope);
    expect(authorTrustPolicy.isTrustedAuthor).toHaveBeenCalledWith(
      envelope.authorPublicKey,
      1_800_000_000_001
    );
    expect(onAccepted).toHaveBeenCalledOnce();

    stop();
    expect(harness.isDetached()).toBe(true);
  });

  it("does not persist a packet rejected by the author trust policy", async () => {
    const harness = createTransportHarness();
    const signatureVerifier = { verify: vi.fn().mockResolvedValue(true) };
    const authorTrustPolicy = { isTrustedAuthor: vi.fn().mockResolvedValue(false) };
    const onRejected = vi.fn();

    vi.mocked(storeVerifiedEvent).mockImplementation(async (_candidate, verifier) => {
      if (!(await verifier.verify(envelope))) {
        throw new Error("Rejected by verifier");
      }
      return true;
    });

    attachVerifiedEventIngress(harness.transport, {
      signatureVerifier,
      authorTrustPolicy,
      onRejected
    });
    harness.emit("peer-a", encodeRelayPacket(envelope, {
      hopCount: 1,
      maxHops: 5
    }));

    await vi.waitFor(() => {
      expect(onRejected).toHaveBeenCalledWith("peer-a", "storage_rejected");
    });
    expect(authorTrustPolicy.isTrustedAuthor).toHaveBeenCalledOnce();
  });

  it("rejects malformed packets without calling storage", async () => {
    const harness = createTransportHarness();
    const onRejected = vi.fn();
    attachVerifiedEventIngress(harness.transport, {
      signatureVerifier: { verify: vi.fn().mockResolvedValue(true) },
      authorTrustPolicy: { isTrustedAuthor: vi.fn().mockResolvedValue(true) },
      onRejected
    });

    harness.emit("peer-a", new TextEncoder().encode("{"));

    await vi.waitFor(() => {
      expect(onRejected).toHaveBeenCalledWith("peer-a", "invalid_packet");
    });
    expect(storeVerifiedEvent).not.toHaveBeenCalled();
  });
});
