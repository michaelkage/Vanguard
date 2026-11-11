import { requireNativeModule, EventEmitter } from "expo-modules-core";

export interface NearbyPeer {
  readonly endpointId: string;
  readonly endpointName: string;
  readonly serviceId: string;
}

export interface ConnectionRequest {
  readonly endpointId: string;
  readonly endpointName: string;
  readonly authenticationDigits: string;
  readonly isIncomingConnection: boolean;
}

export interface NearbyPayload {
  readonly endpointId: string;
  readonly payloadBase64Url: string;
  readonly byteLength: number;
}

export interface PayloadTransferUpdate {
  readonly endpointId: string;
  readonly payloadId: number;
  readonly status: "success" | "failure" | "canceled" | "in_progress" | "unknown";
  readonly bytesTransferred: number;
  readonly totalBytes: number;
}

interface NativeNearbyModule {
  getMissingPermissions(): Promise<string[]>;
  startAdvertising(serviceId: string, endpointName: string): Promise<void>;
  startDiscovery(serviceId: string): Promise<void>;
  requestConnection(endpointId: string): Promise<void>;
  acceptConnection(endpointId: string): Promise<void>;
  rejectConnection(endpointId: string): Promise<void>;
  sendBytes(endpointId: string, payloadBase64Url: string): Promise<{ queued: boolean; byteLength: number }>;
  disconnect(endpointId: string): Promise<void>;
  stop(): Promise<void>;
}

const native = requireNativeModule<NativeNearbyModule>("VanguardNearby");
const emitter = new EventEmitter(native as never);

export const VanguardNearby = {
  getMissingPermissions: () => native.getMissingPermissions(),
  startAdvertising: (serviceId: string, endpointName: string) =>
    native.startAdvertising(serviceId, endpointName),
  startDiscovery: (serviceId: string) => native.startDiscovery(serviceId),
  requestConnection: (endpointId: string) => native.requestConnection(endpointId),
  acceptConnection: (endpointId: string) => native.acceptConnection(endpointId),
  rejectConnection: (endpointId: string) => native.rejectConnection(endpointId),
  sendBytes: (endpointId: string, payloadBase64Url: string) =>
    native.sendBytes(endpointId, payloadBase64Url),
  disconnect: (endpointId: string) => native.disconnect(endpointId),
  stop: () => native.stop(),
  addPeerFoundListener: (listener: (peer: NearbyPeer) => void) =>
    emitter.addListener("onPeerFound", listener),
  addPeerLostListener: (listener: (event: { endpointId: string }) => void) =>
    emitter.addListener("onPeerLost", listener),
  addConnectionInitiatedListener: (listener: (request: ConnectionRequest) => void) =>
    emitter.addListener("onConnectionInitiated", listener),
  addConnectionStateListener: (listener: (event: { endpointId: string; state: string; statusCode?: number }) => void) =>
    emitter.addListener("onConnectionStateChanged", listener),
  addPayloadListener: (listener: (payload: NearbyPayload) => void) =>
    emitter.addListener("onPayloadReceived", listener),
  addPayloadTransferListener: (listener: (update: PayloadTransferUpdate) => void) =>
    emitter.addListener("onPayloadTransferUpdate", listener),
  addTransportErrorListener: (listener: (error: { code: string; endpointId?: string }) => void) =>
    emitter.addListener("onTransportError", listener),
  addTransportStateListener: (listener: (event: { state: string }) => void) =>
    emitter.addListener("onTransportStateChanged", listener)
};

export function encodeBytesBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function decodeBytesBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new TypeError("Invalid base64url payload");
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64 + "=".repeat((4 - base64.length % 4) % 4));
  const bytes = Uint8Array.from(binary, character => character.charCodeAt(0));
  if (encodeBytesBase64Url(bytes) !== value) throw new TypeError("Non-canonical base64url payload");
  return bytes;
}
