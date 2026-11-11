import type { SignatureVerifier } from "../storage/event-repository";
import {
  attachVerifiedEventIngress,
  type AuthorTrustPolicy,
  type IngressRejectionReason,
  type RelayPacket,
  type VerifiedIngressOptions
} from "./event-ingress";
import type {
  NearbyConnectionRequest,
  NearbyPeer,
  NearbyTransport,
  NearbyTransferUpdate
} from "./transport";

export type MeshSessionState = "stopped" | "starting" | "running" | "stopping";

export interface MeshSessionCallbacks {
  readonly onPeerFound?: (peer: NearbyPeer) => void;
  readonly onPeerLost?: (deviceId: string) => void;
  /** Every request requires an explicit acceptConnection() or rejectConnection(). */
  readonly onConnectionRequest?: (request: NearbyConnectionRequest) => void;
  readonly onTransferUpdate?: (update: NearbyTransferUpdate) => void;
  readonly onTransportError?: (error: { code: string; deviceId?: string }) => void;
  readonly onEventAccepted?: VerifiedIngressOptions["onAccepted"];
  readonly onEventRejected?: (
    peerDeviceId: string,
    reason: IngressRejectionReason
  ) => void;
}

export interface MeshSessionOptions extends MeshSessionCallbacks {
  readonly transport: NearbyTransport;
  readonly serviceId: string;
  readonly endpointName: string;
  readonly signatureVerifier: SignatureVerifier;
  readonly authorTrustPolicy: AuthorTrustPolicy;
  readonly maxHops?: number;
  readonly nowEpochMs?: () => number;
}

/**
 * Owns the complete Nearby session lifecycle. Radio discovery is deliberately
 * opportunistic: Android may suspend background work, so callers must not treat
 * a running session as a guarantee of continuous discovery.
 *
 * Incoming and outgoing connection negotiations are surfaced to the caller;
 * this class never accepts a connection implicitly. Received event packets are
 * signature-checked and passed through the fail-closed author trust policy
 * before the event repository can persist them.
 */
export class NearbyMeshSession {
  private currentState: MeshSessionState = "stopped";
  private startOperation: Promise<void> | undefined;
  private stopOperation: Promise<void> | undefined;
  private detachIngress: (() => void) | undefined;
  private readonly detachListeners: Array<() => void> = [];
  private readonly pendingConnections = new Set<string>();

  constructor(private readonly options: MeshSessionOptions) {
    if (!options.serviceId.trim()) throw new TypeError("serviceId is required");
    if (!options.endpointName.trim()) throw new TypeError("endpointName is required");
    if (!options.signatureVerifier || !options.authorTrustPolicy) {
      throw new TypeError("Signature verification and author trust policy are required");
    }
  }

  get state(): MeshSessionState {
    return this.currentState;
  }

  get pendingConnectionDeviceIds(): readonly string[] {
    return [...this.pendingConnections];
  }

  start(): Promise<void> {
    if (this.currentState === "running") return Promise.resolve();
    if (this.startOperation) return this.startOperation;
    if (this.stopOperation) {
      return this.stopOperation.then(() => this.start());
    }

    this.currentState = "starting";
    this.startOperation = this.startInternal().finally(() => {
      this.startOperation = undefined;
    });
    return this.startOperation;
  }

  private async startInternal(): Promise<void> {
    try {
      this.attachListeners();
      this.detachIngress = attachVerifiedEventIngress(this.options.transport, {
        signatureVerifier: this.options.signatureVerifier,
        authorTrustPolicy: this.options.authorTrustPolicy,
        ...(this.options.maxHops === undefined ? {} : { maxHops: this.options.maxHops }),
        ...(this.options.nowEpochMs === undefined ? {} : { nowEpochMs: this.options.nowEpochMs }),
        ...(this.options.onEventAccepted === undefined
          ? {}
          : { onAccepted: this.options.onEventAccepted }),
        ...(this.options.onEventRejected === undefined
          ? {}
          : { onRejected: this.options.onEventRejected })
      });

      // Await both operations even if one fails so rollback cannot race a
      // still-running advertiser/discovery start request.
      const outcomes = await Promise.allSettled([
        this.options.transport.startAdvertising(
          this.options.serviceId,
          this.options.endpointName
        ),
        this.options.transport.startDiscovery(this.options.serviceId)
      ]);
      const failure = outcomes.find(
        (outcome): outcome is PromiseRejectedResult => outcome.status === "rejected"
      );
      if (failure) throw failure.reason;
      this.currentState = "running";
    } catch (error) {
      try {
        await this.teardown();
      } catch (cleanupError) {
        this.currentState = "stopped";
        throw new AggregateError(
          [error, cleanupError],
          "Nearby session startup failed and rollback was incomplete"
        );
      }
      this.currentState = "stopped";
      throw error;
    }
  }

  private attachListeners(): void {
    const transport = this.options.transport;
    // Register each disposer immediately so a later subscription failure
    // cannot leak listeners created earlier in this method.
    this.detachListeners.push(
      transport.addPeerListener(peer => this.notify(() => this.options.onPeerFound?.(peer)))
    );
    this.detachListeners.push(
      transport.addPeerLostListener(deviceId =>
        this.notify(() => this.options.onPeerLost?.(deviceId))
      )
    );
    this.detachListeners.push(
      transport.addConnectionRequestListener(request => {
        this.pendingConnections.add(request.deviceId);
        this.notify(() => this.options.onConnectionRequest?.(request));
      })
    );
    this.detachListeners.push(
      transport.addTransferListener(update =>
        this.notify(() => this.options.onTransferUpdate?.(update))
      )
    );
    this.detachListeners.push(
      transport.addErrorListener(error =>
        this.notify(() => this.options.onTransportError?.(error))
      )
    );
  }

  async connect(deviceId: string): Promise<void> {
    this.assertRunning();
    this.assertDeviceId(deviceId);
    await this.options.transport.connect(deviceId);
  }

  async acceptConnection(deviceId: string): Promise<void> {
    this.assertRunning();
    this.assertPendingConnection(deviceId);
    await this.options.transport.acceptConnection(deviceId);
    this.pendingConnections.delete(deviceId);
  }

  async rejectConnection(deviceId: string): Promise<void> {
    this.assertRunning();
    this.assertPendingConnection(deviceId);
    await this.options.transport.rejectConnection(deviceId);
    this.pendingConnections.delete(deviceId);
  }

  async send(deviceId: string, packet: Uint8Array): Promise<void> {
    this.assertRunning();
    this.assertDeviceId(deviceId);
    await this.options.transport.send(deviceId, packet);
  }

  async disconnect(deviceId: string): Promise<void> {
    this.assertRunning();
    this.assertDeviceId(deviceId);
    await this.options.transport.disconnect(deviceId);
    this.pendingConnections.delete(deviceId);
  }

  stop(): Promise<void> {
    if (this.currentState === "stopped") return Promise.resolve();
    if (this.stopOperation) return this.stopOperation;

    this.currentState = "stopping";
    this.stopOperation = (async () => {
      if (this.startOperation) {
        try {
          await this.startOperation;
        } catch {
          // startInternal already performs rollback before rejecting.
        }
      }
      try {
        await this.teardown();
      } finally {
        this.currentState = "stopped";
      }
    })().finally(() => {
      this.stopOperation = undefined;
    });
    return this.stopOperation;
  }

  private async teardown(): Promise<void> {
    this.detachIngress?.();
    this.detachIngress = undefined;
    for (const detach of this.detachListeners.splice(0).reverse()) {
      try {
        detach();
      } catch {
        // Continue releasing the remaining listeners.
      }
    }
    this.pendingConnections.clear();
    await this.options.transport.stop();
  }

  private assertRunning(): void {
    if (this.currentState !== "running") {
      throw new Error(`Mesh session is not running (state: ${this.currentState})`);
    }
  }

  private assertDeviceId(deviceId: string): void {
    if (!deviceId.trim()) throw new TypeError("deviceId is required");
  }

  private assertPendingConnection(deviceId: string): void {
    this.assertDeviceId(deviceId);
    if (!this.pendingConnections.has(deviceId)) {
      throw new Error("No pending connection request exists for this device");
    }
  }

  private notify(callback: () => void): void {
    try {
      callback();
    } catch {
      // UI observers must not interrupt transport lifecycle or ingress.
    }
  }
}
