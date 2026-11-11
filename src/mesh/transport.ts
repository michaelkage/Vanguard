export interface NearbyPeer {
  readonly deviceId: string;
  readonly displayName: string;
}

export type TransportState = "idle" | "advertising" | "discovering" | "connected";

export interface NearbyTransport {
  readonly state: TransportState;
  startAdvertising(serviceId: string): Promise<void>;
  startDiscovery(serviceId: string): Promise<void>;
  connect(deviceId: string): Promise<void>;
  send(deviceId: string, payload: Uint8Array): Promise<void>;
  disconnect(deviceId: string): Promise<void>;
  stop(): Promise<void>;
  addPeerListener(listener: (peer: NearbyPeer) => void): () => void;
  addPayloadListener(listener: (deviceId: string, payload: Uint8Array) => void): () => void;
}

/**
 * The application depends on this contract, not on a particular radio library.
 * Android Nearby Connections and a future iOS transport will implement it natively.
 */
