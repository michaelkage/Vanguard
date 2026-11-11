import { Platform } from "react-native";
import {
  VanguardNearby,
  encodeBytesBase64Url,
  decodeBytesBase64Url,
  type ConnectionRequest,
  type NearbyPeer as NativeNearbyPeer,
  type NearbyPayload
} from "../../modules/vanguard-nearby/src";
import { requestVanguardNearbyPermissions } from "./request-permissions";

export interface NearbyPeer {
  readonly deviceId: string;
  readonly displayName: string;
}

export type TransportState = "idle" | "advertising" | "discovering" | "connected";

export interface NearbyConnectionRequest {
  readonly deviceId: string;
  readonly displayName: string;
  /** Nearby's short authentication code; both users should compare it out of band. */
  readonly authenticationDigits: string;
  readonly isIncomingConnection: boolean;
}

export interface NearbyTransport {
  readonly state: TransportState;
  startAdvertising(serviceId: string, endpointName: string): Promise<void>;
  startDiscovery(serviceId: string): Promise<void>;
  connect(deviceId: string): Promise<void>;
  acceptConnection(deviceId: string): Promise<void>;
  rejectConnection(deviceId: string): Promise<void>;
  send(deviceId: string, payload: Uint8Array): Promise<void>;
  disconnect(deviceId: string): Promise<void>;
  stop(): Promise<void>;
  addPeerListener(listener: (peer: NearbyPeer) => void): () => void;
  addConnectionRequestListener(listener: (request: NearbyConnectionRequest) => void): () => void;
  addPayloadListener(listener: (deviceId: string, payload: Uint8Array) => void): () => void;
}

type Listener<T> = (value: T) => void;

function mapPeer(peer: NativeNearbyPeer): NearbyPeer {
  return { deviceId: peer.endpointId, displayName: peer.endpointName };
}

function mapConnectionRequest(request: ConnectionRequest): NearbyConnectionRequest {
  return {
    deviceId: request.endpointId,
    displayName: request.endpointName,
    authenticationDigits: request.authenticationDigits,
    isIncomingConnection: request.isIncomingConnection
  };
}

function mapPayload(payload: NearbyPayload): { deviceId: string; bytes: Uint8Array } {
  return {
    deviceId: payload.endpointId,
    bytes: decodeBytesBase64Url(payload.payloadBase64Url)
  };
}

/**
 * Android implementation backed by Google Play services Nearby Connections.
 * The link is encrypted, but it does not establish author identity. Every
 * received Vanguard event must pass protocol signature verification first.
 */
export class AndroidNearbyTransport implements NearbyTransport {
  private currentState: TransportState = "idle";
  private readonly connected = new Set<string>();
  private readonly peerListeners = new Set<Listener<NearbyPeer>>();
  private readonly connectionRequestListeners = new Set<Listener<NearbyConnectionRequest>>();
  private readonly payloadListeners = new Set<Listener<{ deviceId: string; payload: Uint8Array }>>();
  private readonly subscriptions: Array<{ remove(): void }>;

  constructor() {
    if (Platform.OS !== "android") {
      throw new Error("AndroidNearbyTransport can only be created on Android");
    }

    this.subscriptions = [
      VanguardNearby.addPeerFoundListener(peer => {
        const mapped = mapPeer(peer);
        this.peerListeners.forEach(listener => listener(mapped));
      }),
      VanguardNearby.addConnectionInitiatedListener(request => {
        const mapped = mapConnectionRequest(request);
        this.connectionRequestListeners.forEach(listener => listener(mapped));
      }),
      VanguardNearby.addConnectionStateListener(event => {
        if (event.state === "connected") {
          this.connected.add(event.endpointId);
          this.currentState = "connected";
        } else {
          this.connected.delete(event.endpointId);
          if (this.connected.size === 0 && this.currentState === "connected") {
            this.currentState = "idle";
          }
        }
      }),
      VanguardNearby.addPayloadListener(payload => {
        const mapped = mapPayload(payload);
        this.payloadListeners.forEach(listener => listener(mapped));
      }),
      VanguardNearby.addTransportStateListener(event => {
        if (event.state === "idle" || event.state === "advertising" || event.state === "discovering") {
          this.currentState = this.connected.size > 0 ? "connected" : event.state;
        }
      })
    ];
  }

  get state(): TransportState {
    return this.currentState;
  }

  async startAdvertising(serviceId: string, endpointName: string): Promise<void> {
    await this.ensurePermissions();
    await VanguardNearby.startAdvertising(serviceId, endpointName);
    if (this.connected.size === 0) this.currentState = "advertising";
  }

  async startDiscovery(serviceId: string): Promise<void> {
    await this.ensurePermissions();
    await VanguardNearby.startDiscovery(serviceId);
    if (this.connected.size === 0) this.currentState = "discovering";
  }

  async connect(deviceId: string): Promise<void> {
    await VanguardNearby.requestConnection(deviceId);
  }

  acceptConnection(deviceId: string): Promise<void> {
    return VanguardNearby.acceptConnection(deviceId);
  }

  rejectConnection(deviceId: string): Promise<void> {
    return VanguardNearby.rejectConnection(deviceId);
  }

  async send(deviceId: string, payload: Uint8Array): Promise<void> {
    if (payload.byteLength === 0 || payload.byteLength > 24 * 1024) {
      throw new RangeError("Vanguard mesh packets must contain 1-24576 bytes");
    }
    await VanguardNearby.sendBytes(deviceId, encodeBytesBase64Url(payload));
  }

  async disconnect(deviceId: string): Promise<void> {
    await VanguardNearby.disconnect(deviceId);
    this.connected.delete(deviceId);
    if (this.connected.size === 0) this.currentState = "idle";
  }

  async stop(): Promise<void> {
    await VanguardNearby.stop();
    this.connected.clear();
    this.currentState = "idle";
  }

  addPeerListener(listener: Listener<NearbyPeer>): () => void {
    this.peerListeners.add(listener);
    return () => this.peerListeners.delete(listener);
  }

  addConnectionRequestListener(listener: Listener<NearbyConnectionRequest>): () => void {
    this.connectionRequestListeners.add(listener);
    return () => this.connectionRequestListeners.delete(listener);
  }

  addPayloadListener(listener: Listener<{ deviceId: string; payload: Uint8Array }>): () => void {
    this.payloadListeners.add(listener);
    return () => this.payloadListeners.delete(listener);
  }

  dispose(): void {
    this.subscriptions.forEach(subscription => subscription.remove());
    this.peerListeners.clear();
    this.connectionRequestListeners.clear();
    this.payloadListeners.clear();
  }

  private async ensurePermissions(): Promise<void> {
    const granted = await requestVanguardNearbyPermissions();
    if (!granted) throw new Error("Nearby permissions were denied");
  }
}
