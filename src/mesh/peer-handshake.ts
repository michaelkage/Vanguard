import type { AuthorTrustPolicy } from "./event-ingress";

export type PeerHandshakeRole = "initiator" | "responder";
export type PeerHandshakeState =
  | "created" | "awaiting_response" | "awaiting_ack" | "awaiting_finish"
  | "established" | "failed" | "disposed";

export interface PeerHandshakeCrypto {
  getIdentity(): Promise<{ readonly publicKey: string }>;
  randomBytes(length: number): Promise<Uint8Array>;
  createEphemeralKeyPair(): Promise<{ readonly handle: string; readonly publicKey: string }>;
  signIdentity(message: string): Promise<string>;
  verifyIdentity(publicKey: string, message: string, signature: string): Promise<boolean>;
  hashBase64Url(message: string): Promise<string>;
  /** Native X25519 + HKDF-SHA-256; traffic keys remain native and only an opaque handle crosses JS. */
  deriveSession(
    ephemeralHandle: string,
    remoteEphemeralPublicKey: string,
    transcriptHash: string,
    role: PeerHandshakeRole
  ): Promise<string>;
  destroyEphemeral(handle: string): Promise<void>;
  destroySession(handle: string): Promise<void>;
}

export interface PeerHandshakeOptions {
  readonly crypto: PeerHandshakeCrypto;
  readonly authorTrustPolicy: AuthorTrustPolicy;
  readonly nowEpochMs: () => number;
}

export interface PeerHandshakeHello {
  readonly version: 1;
  readonly type: "hello";
  readonly sessionId: string;
  readonly initiatorPublicKey: string;
  readonly initiatorEphemeralPublicKey: string;
  readonly initiatorNonce: string;
  readonly signature: string;
}

export interface PeerHandshakeResponse {
  readonly version: 1;
  readonly type: "response";
  readonly sessionId: string;
  readonly initiatorHelloHash: string;
  readonly responderPublicKey: string;
  readonly responderEphemeralPublicKey: string;
  readonly responderNonce: string;
  readonly signature: string;
}

export interface PeerHandshakeFinish {
  readonly version: 1;
  readonly type: "finish";
  readonly sessionId: string;
  readonly transcriptHash: string;
  readonly signature: string;
}

export interface PeerHandshakeAck {
  readonly version: 1;
  readonly type: "ack";
  readonly sessionId: string;
  readonly transcriptHash: string;
  readonly signature: string;
}

export interface EstablishedPeerSession {
  readonly sessionId: string;
  readonly remotePublicKey: string;
  readonly cryptoSessionHandle: string;
}

const HELLO_DOMAIN = "VANGUARD_PEER_HELLO_V1\n";
const RESPONSE_DOMAIN = "VANGUARD_PEER_RESPONSE_V1\n";
const FINISH_DOMAIN = "VANGUARD_PEER_FINISH_V1\n";
const ACK_DOMAIN = "VANGUARD_PEER_ACK_V1\n";
const TRANSCRIPT_DOMAIN = "VANGUARD_PEER_TRANSCRIPT_V1";
const KEY = /^[A-Za-z0-9_-]{59}$/;
const SIG = /^[A-Za-z0-9_-]{86}$/;
const NONCE = /^[A-Za-z0-9_-]{43}$/;
const SESSION = /^[A-Za-z0-9_-]{22}$/;

function record(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError("Handshake message must be an object");
  }
  const item = value as Record<string, unknown>;
  const actual = Object.keys(item).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new TypeError("Handshake message has missing or unexpected fields");
  }
  return item;
}

function field(item: Record<string, unknown>, name: string, pattern: RegExp): string {
  const value = item[name];
  if (typeof value !== "string" || !pattern.test(value)) {
    throw new TypeError("Invalid handshake field: " + name);
  }
  return value;
}

function validateHello(value: unknown): asserts value is PeerHandshakeHello {
  const item = record(value, [
    "version", "type", "sessionId", "initiatorPublicKey",
    "initiatorEphemeralPublicKey", "initiatorNonce", "signature"
  ]);
  if (item.version !== 1 || item.type !== "hello") throw new TypeError("Unsupported hello message");
  field(item, "sessionId", SESSION);
  field(item, "initiatorPublicKey", KEY);
  field(item, "initiatorEphemeralPublicKey", KEY);
  field(item, "initiatorNonce", NONCE);
  field(item, "signature", SIG);
}

function validateResponse(value: unknown): asserts value is PeerHandshakeResponse {
  const item = record(value, [
    "version", "type", "sessionId", "initiatorHelloHash", "responderPublicKey",
    "responderEphemeralPublicKey", "responderNonce", "signature"
  ]);
  if (item.version !== 1 || item.type !== "response") throw new TypeError("Unsupported response message");
  field(item, "sessionId", SESSION);
  field(item, "initiatorHelloHash", NONCE);
  field(item, "responderPublicKey", KEY);
  field(item, "responderEphemeralPublicKey", KEY);
  field(item, "responderNonce", NONCE);
  field(item, "signature", SIG);
}

function validateTerminal(
  value: unknown,
  type: "finish" | "ack"
): asserts value is PeerHandshakeFinish | PeerHandshakeAck {
  const item = record(value, ["version", "type", "sessionId", "transcriptHash", "signature"]);
  if (item.version !== 1 || item.type !== type) throw new TypeError("Unsupported " + type + " message");
  field(item, "sessionId", SESSION);
  field(item, "transcriptHash", NONCE);
  field(item, "signature", SIG);
}

function helloUnsigned(value: PeerHandshakeHello): string {
  return JSON.stringify({
    version: 1, type: "hello", sessionId: value.sessionId,
    initiatorPublicKey: value.initiatorPublicKey,
    initiatorEphemeralPublicKey: value.initiatorEphemeralPublicKey,
    initiatorNonce: value.initiatorNonce
  });
}

function responseUnsigned(value: PeerHandshakeResponse): string {
  return JSON.stringify({
    version: 1, type: "response", sessionId: value.sessionId,
    initiatorHelloHash: value.initiatorHelloHash,
    responderPublicKey: value.responderPublicKey,
    responderEphemeralPublicKey: value.responderEphemeralPublicKey,
    responderNonce: value.responderNonce
  });
}

function transcript(hello: PeerHandshakeHello, response: PeerHandshakeResponse): string {
  return JSON.stringify({
    domain: TRANSCRIPT_DOMAIN,
    hello: { unsigned: helloUnsigned(hello), signature: hello.signature },
    response: responseUnsigned(response)
  });
}

function encodeUrl(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function trust(options: PeerHandshakeOptions, publicKey: string): Promise<void> {
  const now = options.nowEpochMs();
  if (!Number.isSafeInteger(now) || now < 0) throw new RangeError("Invalid handshake clock");
  if (!(await options.authorTrustPolicy.isTrustedAuthor(publicKey, now))) {
    throw new Error("Peer identity is not trusted by the active author policy");
  }
}

function validateIdentity(publicKey: string): void {
  if (!KEY.test(publicKey)) throw new TypeError("Crypto provider returned an invalid identity key");
}

export class InitiatorPeerHandshake {
  private currentState: PeerHandshakeState = "awaiting_response";
  private ephemeralHandle: string;
  private sessionHandle: string | undefined;
  private response: PeerHandshakeResponse | undefined;
  private transcriptHash: string | undefined;

  private constructor(
    private readonly options: PeerHandshakeOptions,
    readonly hello: PeerHandshakeHello,
    ephemeralHandle: string
  ) {
    this.ephemeralHandle = ephemeralHandle;
  }

  static async begin(options: PeerHandshakeOptions): Promise<InitiatorPeerHandshake> {
    const identity = await options.crypto.getIdentity();
    validateIdentity(identity.publicKey);
    const random = await options.crypto.randomBytes(48);
    if (!(random instanceof Uint8Array) || random.byteLength !== 48) {
      throw new Error("Crypto provider returned invalid handshake randomness");
    }
    const ephemeral = await options.crypto.createEphemeralKeyPair();
    if (!ephemeral.handle || !KEY.test(ephemeral.publicKey)) {
      await options.crypto.destroyEphemeral(ephemeral.handle);
      throw new Error("Crypto provider returned an invalid ephemeral key");
    }
    try {
      const unsigned = {
        version: 1 as const,
        type: "hello" as const,
        sessionId: encodeUrl(random.subarray(0, 16)),
        initiatorPublicKey: identity.publicKey,
        initiatorEphemeralPublicKey: ephemeral.publicKey,
        initiatorNonce: encodeUrl(random.subarray(16))
      };
      const signature = await options.crypto.signIdentity(HELLO_DOMAIN + JSON.stringify(unsigned));
      if (!SIG.test(signature)) throw new Error("Invalid identity signature encoding");
      return new InitiatorPeerHandshake(options, { ...unsigned, signature }, ephemeral.handle);
    } catch (error) {
      await options.crypto.destroyEphemeral(ephemeral.handle);
      throw error;
    }
  }

  get state(): PeerHandshakeState {
    return this.currentState;
  }

  async acceptResponse(candidate: unknown): Promise<PeerHandshakeFinish> {
    if (this.currentState !== "awaiting_response") throw new Error("Handshake is not awaiting a response");
    try {
      validateResponse(candidate);
      const response = candidate;
      if (response.sessionId !== this.hello.sessionId) throw new Error("Response session ID mismatch");
      const helloHash = await this.options.crypto.hashBase64Url(
        HELLO_DOMAIN + helloUnsigned(this.hello) + this.hello.signature
      );
      if (response.initiatorHelloHash !== helloHash) throw new Error("Response does not bind initiator hello");
      const signed = RESPONSE_DOMAIN + response.sessionId + "\n" +
        response.initiatorHelloHash + "\n" +
        response.responderEphemeralPublicKey + "\n" + response.responderNonce;
      if (!(await this.options.crypto.verifyIdentity(response.responderPublicKey, signed, response.signature))) {
        throw new Error("Response signature is invalid");
      }
      await trust(this.options, response.responderPublicKey);
      const transcriptHash = await this.options.crypto.hashBase64Url(transcript(this.hello, response));
      this.sessionHandle = await this.options.crypto.deriveSession(
        this.ephemeralHandle, response.responderEphemeralPublicKey, transcriptHash, "initiator"
      );
      if (!this.sessionHandle) throw new Error("Native crypto provider did not create a session");
      this.response = response;
      this.transcriptHash = transcriptHash;
      const signature = await this.options.crypto.signIdentity(
        FINISH_DOMAIN + response.sessionId + "\n" + transcriptHash
      );
      if (!SIG.test(signature)) throw new Error("Invalid identity signature encoding");
      this.currentState = "awaiting_ack";
      await this.destroyEphemeral();
      return { version: 1, type: "finish", sessionId: response.sessionId, transcriptHash, signature };
    } catch (error) {
      await this.fail();
      throw error;
    }
  }

  async acceptAck(candidate: unknown): Promise<EstablishedPeerSession> {
    if (this.currentState !== "awaiting_ack") throw new Error("Handshake is not awaiting acknowledgement");
    try {
      validateTerminal(candidate, "ack");
      const ack = candidate as PeerHandshakeAck;
      const response = this.response;
      const transcriptHash = this.transcriptHash;
      const handle = this.sessionHandle;
      if (!response || !transcriptHash || !handle) throw new Error("Initiator handshake state is incomplete");
      if (ack.sessionId !== this.hello.sessionId || ack.transcriptHash !== transcriptHash) {
        throw new Error("Acknowledgement transcript mismatch");
      }
      const signed = ACK_DOMAIN + ack.sessionId + "\n" + ack.transcriptHash;
      if (!(await this.options.crypto.verifyIdentity(response.responderPublicKey, signed, ack.signature))) {
        throw new Error("Acknowledgement signature is invalid");
      }
      this.currentState = "established";
      return Object.freeze({
        sessionId: ack.sessionId,
        remotePublicKey: response.responderPublicKey,
        cryptoSessionHandle: handle
      });
    } catch (error) {
      await this.fail();
      throw error;
    }
  }

  async dispose(): Promise<void> {
    if (this.currentState === "disposed") return;
    await this.destroyEphemeral();
    if (this.sessionHandle && this.currentState !== "established") {
      await this.options.crypto.destroySession(this.sessionHandle);
    }
    this.currentState = "disposed";
  }

  private async destroyEphemeral(): Promise<void> {
    const handle = this.ephemeralHandle;
    this.ephemeralHandle = "";
    if (handle) await this.options.crypto.destroyEphemeral(handle);
  }

  private async fail(): Promise<void> {
    await this.destroyEphemeral();
    if (this.sessionHandle) {
      const handle = this.sessionHandle;
      this.sessionHandle = undefined;
      await this.options.crypto.destroySession(handle);
    }
    this.currentState = "failed";
  }
}

export class ResponderPeerHandshake {
  private currentState: PeerHandshakeState = "awaiting_finish";
  private constructor(
    private readonly options: PeerHandshakeOptions,
    private readonly hello: PeerHandshakeHello,
    private readonly response: PeerHandshakeResponse,
    private readonly transcriptHash: string,
    private sessionHandle: string
  ) {}

  static async acceptHello(
    candidate: unknown,
    options: PeerHandshakeOptions
  ): Promise<{ readonly handshake: ResponderPeerHandshake; readonly response: PeerHandshakeResponse }> {
    validateHello(candidate);
    const hello = candidate;
    if (!(await options.crypto.verifyIdentity(
      hello.initiatorPublicKey, HELLO_DOMAIN + helloUnsigned(hello), hello.signature
    ))) throw new Error("Hello signature is invalid");
    await trust(options, hello.initiatorPublicKey);
    const identity = await options.crypto.getIdentity();
    validateIdentity(identity.publicKey);
    const random = await options.crypto.randomBytes(32);
    if (!(random instanceof Uint8Array) || random.byteLength !== 32) {
      throw new Error("Crypto provider returned invalid responder randomness");
    }
    const ephemeral = await options.crypto.createEphemeralKeyPair();
    if (!ephemeral.handle || !KEY.test(ephemeral.publicKey)) {
      await options.crypto.destroyEphemeral(ephemeral.handle);
      throw new Error("Crypto provider returned an invalid ephemeral key");
    }
    let sessionHandle: string | undefined;
    try {
      const unsigned = {
        version: 1 as const,
        type: "response" as const,
        sessionId: hello.sessionId,
        initiatorHelloHash: await options.crypto.hashBase64Url(
          HELLO_DOMAIN + helloUnsigned(hello) + hello.signature
        ),
        responderPublicKey: identity.publicKey,
        responderEphemeralPublicKey: ephemeral.publicKey,
        responderNonce: encodeUrl(random)
      };
      const signed = RESPONSE_DOMAIN + unsigned.sessionId + "\n" +
        unsigned.initiatorHelloHash + "\n" +
        unsigned.responderEphemeralPublicKey + "\n" + unsigned.responderNonce;
      const signature = await options.crypto.signIdentity(signed);
      if (!SIG.test(signature)) throw new Error("Invalid identity signature encoding");
      const response = { ...unsigned, signature };
      const transcriptHash = await options.crypto.hashBase64Url(transcript(hello, response));
      sessionHandle = await options.crypto.deriveSession(
        ephemeral.handle, hello.initiatorEphemeralPublicKey, transcriptHash, "responder"
      );
      if (!sessionHandle) throw new Error("Native crypto provider did not create a session");
      return {
        handshake: new ResponderPeerHandshake(options, hello, response, transcriptHash, sessionHandle),
        response
      };
    } catch (error) {
      if (sessionHandle) await options.crypto.destroySession(sessionHandle);
      throw error;
    } finally {
      await options.crypto.destroyEphemeral(ephemeral.handle);
    }
  }

  get state(): PeerHandshakeState {
    return this.currentState;
  }

  async acceptFinish(candidate: unknown): Promise<{
    readonly ack: PeerHandshakeAck;
    readonly session: EstablishedPeerSession;
  }> {
    if (this.currentState !== "awaiting_finish") throw new Error("Handshake is not awaiting finish");
    try {
      validateTerminal(candidate, "finish");
      const finish = candidate as PeerHandshakeFinish;
      if (finish.sessionId !== this.hello.sessionId || finish.transcriptHash !== this.transcriptHash) {
        throw new Error("Finish transcript mismatch");
      }
      const signed = FINISH_DOMAIN + finish.sessionId + "\n" + finish.transcriptHash;
      if (!(await this.options.crypto.verifyIdentity(
        this.hello.initiatorPublicKey, signed, finish.signature
      ))) throw new Error("Finish signature is invalid");
      const ackSignature = await this.options.crypto.signIdentity(
        ACK_DOMAIN + finish.sessionId + "\n" + finish.transcriptHash
      );
      if (!SIG.test(ackSignature)) throw new Error("Invalid identity signature encoding");
      const session = Object.freeze({
        sessionId: finish.sessionId,
        remotePublicKey: this.hello.initiatorPublicKey,
        cryptoSessionHandle: this.sessionHandle
      });
      this.currentState = "established";
      return {
        session,
        ack: {
          version: 1, type: "ack", sessionId: finish.sessionId,
          transcriptHash: finish.transcriptHash, signature: ackSignature
        }
      };
    } catch (error) {
      await this.fail();
      throw error;
    }
  }

  async dispose(): Promise<void> {
    if (this.currentState === "disposed") return;
    if (this.currentState !== "established" && this.sessionHandle) {
      await this.options.crypto.destroySession(this.sessionHandle);
    }
    this.currentState = "disposed";
  }

  private async fail(): Promise<void> {
    if (this.sessionHandle) {
      const handle = this.sessionHandle;
      this.sessionHandle = "";
      await this.options.crypto.destroySession(handle);
    }
    this.currentState = "failed";
  }
}
