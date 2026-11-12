# Authenticated peer-session reference v1

Status: Kotlin/JVM reference implementation; Android transport integration is not complete.

This protocol is separate from the signed event envelope. Ed25519 authenticates the peer handshake. Fresh X25519 ephemeral key pairs derive session traffic keys. The Ed25519 signing key is never used for key agreement.

## Trust prerequisites

Both peers must supply:

- An Ed25519 identity signer/verifier.
- A fail-closed campus author-trust policy that rejects unknown, suspended, revoked, and stale identities.
- A replay guard that atomically claims the initiator's session ID and nonce.

The responder checks the initiator signature and author trust before claiming replay state. The initiator checks the responder signature and author trust before accepting the derived session. A valid signature proves control of a key; it does not independently prove campus enrollment.

## Handshake wire framing

All integer fields are big-endian encodings; the current Kotlin implementation uses a 32-bit version field and a 64-bit packet sequence field with non-negative values.

The fixed-width handshake frame layout is:

| Field | Hello | Response |
|---|---:|---:|
| Magic (VGH1) | 4 bytes | 4 bytes |
| Frame type | 1 | 2 |
| Version | 4 bytes | 4 bytes |
| Session ID | 16 bytes | 16 bytes |
| Initiator nonce | 32 bytes | 32 bytes |
| Responder nonce | — | 32 bytes |
| X25519 ephemeral SPKI | 44 bytes | 44 bytes |
| Ed25519 identity SPKI | 44 bytes | 44 bytes |
| Ed25519 signature | 64 bytes | 64 bytes |

The codec rejects wrong frame types, invalid fixed field lengths, unsupported versions, malformed SPKI encodings, and trailing bytes. Handshake frames are bounded by the same 24 KiB transport ceiling used by Nearby Connections.

## Signed transcript

The signature input uses deterministic binary field framing. Each field is prefixed by a 32-bit big-endian byte length.

Initiator signature input:

    encodeFields("VANGUARD_PEER_HELLO_V1", version, sessionId, initiatorNonce, initiatorEphemeralSpki, initiatorIdentitySpki)

Responder signature input:

    encodeFields("VANGUARD_PEER_RESPONSE_V1", encodeHelloIncludingSignature, version, sessionId, initiatorNonce, responderNonce, responderEphemeralSpki, responderIdentitySpki)

The response therefore binds the complete initiator hello, both nonces, both ephemeral keys, and both identity keys. The transcript hash is SHA-256 over the length-framed complete hello, unsigned response, and responder signature.

## Traffic-key derivation

1. Each peer performs X25519 with its ephemeral private key and the other peer's ephemeral public key.
2. Derive 72 bytes with HKDF-SHA-256:
   - IKM: X25519 shared secret.
   - Salt: handshake transcript SHA-256.
   - Info: VANGUARD_PEER_TRAFFIC_KEYS_V1.
3. Split the output:
   - Bytes 0–31: initiator-to-responder AES-256 key.
   - Bytes 32–35: initiator-to-responder 4-byte nonce prefix.
   - Bytes 36–67: responder-to-initiator AES-256 key.
   - Bytes 68–71: responder-to-initiator 4-byte nonce prefix.

The shared secret, HKDF output, PRK, and intermediate expansion blocks are cleared from mutable byte arrays after use. Session close clears in-memory traffic keys, nonce prefixes, transcript hash, and the stored remote identity-key copy. JVM/provider internals may retain copies; this is best-effort memory hygiene, not a hardware-isolated secret store.

## Encrypted packet format

Each encrypted packet is:

- 1-byte protocol version.
- 8-byte big-endian sequence number.
- AES-GCM ciphertext including its 16-byte authentication tag.

The 12-byte GCM nonce is the direction-specific 4-byte prefix followed by the 8-byte sequence number. Associated data is length-framed from the packet domain string, transcript hash, direction label, and sequence number.

Each direction has an independent key, nonce prefix, and sequence counter. Receivers accept only the exact next sequence number. Replayed and out-of-order packets are rejected. A failed GCM authentication does not advance the receive counter. Maximum encrypted packet size is 24 KiB; maximum plaintext is 24,551 bytes.

## Replay guard

BoundedInMemoryReplayGuard is synchronized, monotonic-clock-based, TTL-bounded, and capacity-bounded. It fails closed when full. It is process-local and loses state on process death; it is not a durable anti-replay store. A production integration must define whether replay state is persisted or whether the ephemeral-session expiry and server-issued identity state make process-local replay protection sufficient for the product threat model.

## Explicit implementation boundary

Implemented in protocol-core:

- Ed25519-authenticated initiator and responder transcript.
- Fresh X25519 ephemeral agreement.
- HKDF-SHA-256 directional key derivation.
- AES-256-GCM authenticated packet protection.
- Fixed-width hello/response codec.
- Strict per-direction sequence enforcement.
- Bounded process-local replay guard.
- JVM unit tests for handshake, framing, trust rejection, replay, tampering, and payload limits.

Not implemented:

- Adapter from the native Android identity module to these interfaces.
- Android provider/device compatibility validation.
- Integration with Nearby connection acceptance, disconnect, and reconnect lifecycle.
- Durable replay state, handshake expiry/timeout, rekey, and key-confirmation policy.
- Message storage, message receipts, or end-to-end encrypted direct-message UI.
- iOS cryptographic/transport adapter.

Until these are implemented and tested on physical devices, the running app continues to rely only on Google Play services Nearby link encryption. Do not claim that Vanguard currently provides end-to-end encrypted peer messaging.
