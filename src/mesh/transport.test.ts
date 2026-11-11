import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => {
  const listener = () => ({ remove: vi.fn() });
  return {
    requestPermissions: vi.fn<() => Promise<boolean>>(),
    nearby: {
      getMissingPermissions: vi.fn().mockResolvedValue([]),
      startAdvertising: vi.fn().mockResolvedValue(undefined),
      startDiscovery: vi.fn().mockResolvedValue(undefined),
      requestConnection: vi.fn().mockResolvedValue(undefined),
      acceptConnection: vi.fn().mockResolvedValue(undefined),
      rejectConnection: vi.fn().mockResolvedValue(undefined),
      sendBytes: vi.fn().mockResolvedValue({ queued: true, byteLength: 1 }),
      disconnect: vi.fn().mockResolvedValue(undefined),
      stop: vi.fn().mockResolvedValue(undefined),
      addPeerFoundListener: vi.fn(listener),
      addPeerLostListener: vi.fn(listener),
      addConnectionInitiatedListener: vi.fn(listener),
      addConnectionStateListener: vi.fn(listener),
      addPayloadListener: vi.fn(listener),
      addPayloadTransferListener: vi.fn(listener),
      addTransportErrorListener: vi.fn(listener),
      addTransportStateListener: vi.fn(listener)
    }
  };
});

vi.mock("react-native", () => ({
  Platform: { OS: "android" }
}));

vi.mock("../../modules/vanguard-nearby/src", () => ({
  VanguardNearby: mocks.nearby,
  encodeBytesBase64Url: (_bytes: Uint8Array) => "AA",
  decodeBytesBase64Url: (_value: string) => new Uint8Array([0])
}));

vi.mock("./request-permissions", () => ({
  requestVanguardNearbyPermissions: mocks.requestPermissions
}));

import { AndroidNearbyTransport } from "./transport";

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((complete, fail) => {
    resolve = complete;
    reject = fail;
  });
  return { promise, resolve, reject };
}

describe("AndroidNearbyTransport permission coordination", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.nearby.startAdvertising.mockResolvedValue(undefined);
    mocks.nearby.startDiscovery.mockResolvedValue(undefined);
  });

  it("shares one permission prompt across concurrent advertising and discovery", async () => {
    const permission = deferred<boolean>();
    mocks.requestPermissions.mockReturnValue(permission.promise);
    const transport = new AndroidNearbyTransport();

    const advertising = transport.startAdvertising("dev.vanguard.mesh", "Vanguard");
    const discovery = transport.startDiscovery("dev.vanguard.mesh");

    expect(mocks.requestPermissions).toHaveBeenCalledOnce();
    expect(mocks.nearby.startAdvertising).not.toHaveBeenCalled();
    expect(mocks.nearby.startDiscovery).not.toHaveBeenCalled();

    permission.resolve(true);
    await Promise.all([advertising, discovery]);

    expect(mocks.nearby.startAdvertising).toHaveBeenCalledOnce();
    expect(mocks.nearby.startDiscovery).toHaveBeenCalledOnce();
  });

  it("clears the in-flight permission result so later starts recheck permission", async () => {
    mocks.requestPermissions
      .mockResolvedValueOnce(true)
      .mockResolvedValueOnce(false);
    const transport = new AndroidNearbyTransport();

    await transport.startAdvertising("dev.vanguard.mesh", "Vanguard");
    await expect(transport.startDiscovery("dev.vanguard.mesh")).rejects.toThrow(
      "Nearby permissions were denied"
    );

    expect(mocks.requestPermissions).toHaveBeenCalledTimes(2);
    expect(mocks.nearby.startAdvertising).toHaveBeenCalledOnce();
    expect(mocks.nearby.startDiscovery).not.toHaveBeenCalled();
  });

  it("clears a rejected permission request so a subsequent attempt can recover", async () => {
    mocks.requestPermissions
      .mockRejectedValueOnce(new Error("Permission service unavailable"))
      .mockResolvedValueOnce(true);
    const transport = new AndroidNearbyTransport();

    await expect(
      transport.startAdvertising("dev.vanguard.mesh", "Vanguard")
    ).rejects.toThrow("Permission service unavailable");

    await transport.startDiscovery("dev.vanguard.mesh");

    expect(mocks.requestPermissions).toHaveBeenCalledTimes(2);
    expect(mocks.nearby.startDiscovery).toHaveBeenCalledOnce();
  });
});
