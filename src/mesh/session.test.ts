import { describe, expect, it, vi } from "vitest";
import type {
  NearbyConnectionRequest,
  NearbyPeer,
  NearbyTransferUpdate,
  NearbyTransport
} from "./transport";
import { NearbyMeshSession } from "./session";

function createTransportHarness(overrides: Partial<NearbyTransport> = {}) {
  const peerListeners = new Set<(peer: NearbyPeer) => void>();
  const peerLostListeners = new Set<(deviceId: string) => void>();
  const requestListeners = new Set<(request: NearbyConnectionRequest) => void>();
  const payloadListeners = new Set<(deviceId: string, payload: Uint8Array) => void>();
  const transferListeners = new Set<(update: NearbyTransferUpdate) => void>();
  const errorListeners = new Set<(error: { code: string; deviceId?: string }) => void>();

  const transport: NearbyTransport = {
    state: "idle",
    startAdvertising: vi.fn().mockResolvedValue(undefined),
    startDiscovery: vi.fn().mockResolvedValue(undefined),
    connect: vi.fn().mockResolvedValue(undefined),
    acceptConnection: vi.fn().mockResolvedValue(undefined),
    rejectConnection: vi.fn().mockResolvedValue(undefined),
    send: vi.fn().mockResolvedValue(undefined),
    disconnect: vi.fn().mockResolvedValue(undefined),
    stop: vi.fn().mockResolvedValue(undefined),
    addPeerListener: vi.fn(listener => {
      peerListeners.add(listener);
      return () => peerListeners.delete(listener);
    }),
    addPeerLostListener: vi.fn(listener => {
      peerLostListeners.add(listener);
      return () => peerLostListeners.delete(listener);
    }),
    addConnectionRequestListener: vi.fn(listener => {
      requestListeners.add(listener);
      return () => requestListeners.delete(listener);
    }),
    addPayloadListener: vi.fn(listener => {
      payloadListeners.add(listener);
      return () => payloadListeners.delete(listener);
    }),
    addTransferListener: vi.fn(listener => {
      transferListeners.add(listener);
      return () => transferListeners.delete(listener);
    }),
    addErrorListener: vi.fn(listener => {
      errorListeners.add(listener);
      return () => errorListeners.delete(listener);
    }),
    ...overrides
  };

  return {
    transport,
    emitConnectionRequest(request: NearbyConnectionRequest) {
      requestListeners.forEach(listener => listener(request));
    },
    listenerCount() {
      return peerListeners.size + peerLostListeners.size + requestListeners.size +
        payloadListeners.size + transferListeners.size + errorListeners.size;
    }
  };
}

function createSession(transport: NearbyTransport, callbacks = {}) {
  return new NearbyMeshSession({
    transport,
    serviceId: "dev.vanguard.mesh",
    endpointName: "Vanguard device",
    signatureVerifier: { verify: vi.fn().mockResolvedValue(true) },
    authorTrustPolicy: { isTrustedAuthor: vi.fn().mockResolvedValue(true) },
    ...callbacks
  });
}

describe("NearbyMeshSession", () => {
  it("starts advertising and discovery once and tears down all listeners", async () => {
    const harness = createTransportHarness();
    const session = createSession(harness.transport);

    await Promise.all([session.start(), session.start()]);
    expect(session.state).toBe("running");
    expect(harness.transport.startAdvertising).toHaveBeenCalledOnce();
    expect(harness.transport.startDiscovery).toHaveBeenCalledOnce();
    expect(harness.listenerCount()).toBe(6);

    await session.stop();
    expect(session.state).toBe("stopped");
    expect(harness.transport.stop).toHaveBeenCalledOnce();
    expect(harness.listenerCount()).toBe(0);
  });

  it("never accepts a connection without an explicit caller decision", async () => {
    const harness = createTransportHarness();
    const onConnectionRequest = vi.fn();
    const session = createSession(harness.transport, { onConnectionRequest });
    await session.start();

    const request: NearbyConnectionRequest = {
      deviceId: "peer-42",
      displayName: "Nearby peer",
      authenticationDigits: "123456",
      isIncomingConnection: true
    };
    harness.emitConnectionRequest(request);

    expect(onConnectionRequest).toHaveBeenCalledWith(request);
    expect(harness.transport.acceptConnection).not.toHaveBeenCalled();
    expect(session.pendingConnectionDeviceIds).toEqual(["peer-42"]);

    await session.acceptConnection("peer-42");
    expect(harness.transport.acceptConnection).toHaveBeenCalledWith("peer-42");
    expect(session.pendingConnectionDeviceIds).toEqual([]);
    await expect(session.rejectConnection("peer-42")).rejects.toThrow(
      "No pending connection request"
    );
    await session.stop();
  });

  it("allows an explicit rejection of a pending connection", async () => {
    const harness = createTransportHarness();
    const session = createSession(harness.transport);
    await session.start();
    harness.emitConnectionRequest({
      deviceId: "peer-7",
      displayName: "Peer",
      authenticationDigits: "654321",
      isIncomingConnection: true
    });

    await session.rejectConnection("peer-7");
    expect(harness.transport.rejectConnection).toHaveBeenCalledWith("peer-7");
    expect(session.pendingConnectionDeviceIds).toEqual([]);
    await session.stop();
  });

  it("rolls back listeners and transport if either radio start operation fails", async () => {
    const harness = createTransportHarness({
      startDiscovery: vi.fn().mockRejectedValue(new Error("discovery unavailable"))
    });
    const session = createSession(harness.transport);

    await expect(session.start()).rejects.toThrow("discovery unavailable");
    expect(session.state).toBe("stopped");
    expect(harness.transport.stop).toHaveBeenCalledOnce();
    expect(harness.listenerCount()).toBe(0);
  });

  it("rejects transport actions unless the session is running", async () => {
    const harness = createTransportHarness();
    const session = createSession(harness.transport);

    await expect(session.connect("peer-1")).rejects.toThrow("Mesh session is not running");
    await expect(session.send("peer-1", Uint8Array.of(1))).rejects.toThrow(
      "Mesh session is not running"
    );
  });
});
