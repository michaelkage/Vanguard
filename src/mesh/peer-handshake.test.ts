import { describe, expect, it, vi } from "vitest";
import {
  InitiatorPeerHandshake,
  ResponderPeerHandshake,
  type PeerHandshakeCrypto,
  type PeerHandshakeOptions
} from "./peer-handshake";

function provider(publicKey: string): PeerHandshakeCrypto {
  let counter = 0;
  const ephemeral = new Set<string>();
  const encode = (value: string) =>
    btoa(value).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  const signature = (key: string, message: string) => encode(key + ":" + message).slice(0, 86).padEnd(86, "A");
  return {
    getIdentity: async () => ({ publicKey }),
    randomBytes: async length => Uint8Array.from({ length }, (_, index) => (index + ++counter) % 256),
    createEphemeralKeyPair: async () => {
      const handle = "ephemeral-" + (++counter);
      const key = "E" + String(counter).padStart(58, "0");
      ephemeral.add(handle);
      return { handle, publicKey: key };
    },
    signIdentity: async message => signature(publicKey, message),
    verifyIdentity: async (key, message, value) => value === signature(key, message),
    hashBase64Url: async message => encode(message).slice(0, 43).padEnd(43, "A"),
    deriveSession: async (handle, remote, transcript, role) => {
      if (!ephemeral.has(handle) || !remote || !transcript) throw new Error("Invalid derive input");
      return "native-session-" + role + "-" + (++counter);
    },
    destroyEphemeral: async handle => { ephemeral.delete(handle); },
    destroySession: async () => undefined
  };
}

function options(crypto: PeerHandshakeCrypto, trustedKey: string): PeerHandshakeOptions {
  return {
    crypto,
    nowEpochMs: () => 1_800_000_000_000,
    authorTrustPolicy: { isTrustedAuthor: vi.fn(async key => key === trustedKey) }
  };
}

describe("authenticated peer handshake", () => {
  it("requires all four signed messages before both peers are established", async () => {
    const initiatorKey = "I".repeat(59);
    const responderKey = "R".repeat(59);
    const initiator = await InitiatorPeerHandshake.begin(options(provider(initiatorKey), responderKey));
    const { handshake: responder, response } = await ResponderPeerHandshake.acceptHello(
      initiator.hello, options(provider(responderKey), initiatorKey)
    );
    const finish = await initiator.acceptResponse(response);
    expect(initiator.state).toBe("awaiting_ack");
    const { ack, session: responderSession } = await responder.acceptFinish(finish);
    const initiatorSession = await initiator.acceptAck(ack);
    expect(initiator.state).toBe("established");
    expect(responder.state).toBe("established");
    expect(initiatorSession.remotePublicKey).toBe(responderKey);
    expect(responderSession.remotePublicKey).toBe(initiatorKey);
    expect(initiatorSession.sessionId).toBe(responderSession.sessionId);
  });

  it("rejects an identity absent from the local author trust policy", async () => {
    const initiatorKey = "I".repeat(59);
    const responderKey = "R".repeat(59);
    const initiator = await InitiatorPeerHandshake.begin(options(provider(initiatorKey), "X".repeat(59)));
    const { response } = await ResponderPeerHandshake.acceptHello(
      initiator.hello, options(provider(responderKey), initiatorKey)
    );
    await expect(initiator.acceptResponse(response)).rejects.toThrow("not trusted");
    expect(initiator.state).toBe("failed");
  });

  it("rejects a finish message replayed against a different session ID", async () => {
    const initiatorKey = "I".repeat(59);
    const responderKey = "R".repeat(59);
    const initiator = await InitiatorPeerHandshake.begin(options(provider(initiatorKey), responderKey));
    const { handshake: responder, response } = await ResponderPeerHandshake.acceptHello(
      initiator.hello, options(provider(responderKey), initiatorKey)
    );
    const finish = await initiator.acceptResponse(response);
    await expect(responder.acceptFinish({ ...finish, sessionId: "Z".repeat(22) }))
      .rejects.toThrow("transcript mismatch");
    expect(responder.state).toBe("failed");
  });
});
