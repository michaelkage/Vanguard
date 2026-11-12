# Authenticated peer-session reference v2

Status: Kotlin/JVM reference implementation; Android transport integration is not complete.

Ed25519 authenticates the handshake transcript. Fresh X25519 ephemeral key pairs derive session traffic keys. The Ed25519 signing key is never used for key agreement.

## Required caller dependencies

Both peers must supply an Ed25519 identity signer/verifier, a fail-closed campus author-trust policy, an atomic replay guard, and a `HandshakeTimePolicy` backed by a caller-owned rollback-aware epoch clock. There is no system-clock default. A valid signature proves control of a key, not campus enrollment.

## Freshness policy

The initiator captures `createdAtEpochMs` when creating its hello. The timestamp is signed and encoded in the hello frame. The responder validates freshness before signature verification, again immediately before replay-state consumption, and the initiator rechecks it before completing the handshake.

- Maximum hello age: 120,000 ms (inclusive).
- Maximum future clock skew: 30,000 ms (inclusive).
- Default in-memory replay retention: 151,000 ms, covering maximum age plus future skew and a one-second margin.

Every replay guard exposes its guaranteed `retentionMillis`. The responder rejects a guard whose declared retention is shorter than the active time policy's maximum age plus future skew plus a one-second margin, before consuming replay state. If the freshness window is customized, the replay guard must declare a matching retention period. Implementations must not overstate their guarantee. The in-memory guard is process-local and does not survive process death. Caller-supplied rollback detection only detects rollback during the lifetime of that policy; it is not a hardware-backed time anchor across reboot.

## Handshake wire framing

All integers are big-endian. The v2 layout:

| Field | Hello | Response |
|---|---:|---:|
| Magic (VGH2) | 4 bytes | 4 bytes |
| Frame type | 1 | 2 |
| Version | 4 bytes | 4 bytes |
| Creation timestamp | 8 bytes | — |
| Session ID | 16 bytes | 16 bytes |
| Initiator nonce | 32 bytes | 32 bytes |
| Responder nonce | — | 32 bytes |
| X25519 ephemeral SPKI | 44 bytes | 44 bytes |
| Ed25519 identity SPKI | 44 bytes | 44 bytes |
| Ed25519 signature | 64 bytes | 64 bytes |

The v2 wire format and signature domains are incompatible with v1. The codec rejects wrong frame types, unsupported versions, malformed keys, invalid fixed field lengths, and trailing bytes. Frames are bounded by the 24 KiB Nearby payload ceiling.

## Signed transcript and traffic keys

The initiator signature covers length-framed `VANGUARD_PEER_HELLO_V2`, version, creation timestamp, session ID, initiator nonce, initiator ephemeral SPKI, and initiator identity SPKI.

The responder signature covers `VANGUARD_PEER_RESPONSE_V2`, the complete signed initiator hello, version, session ID, both nonces, responder ephemeral SPKI, and responder identity SPKI.

Both peers perform X25519 and derive 72 bytes with HKDF-SHA-256. The transcript hash is the salt and `VANGUARD_PEER_TRAFFIC_KEYS_V2` is the info string. The output contains independent 32-byte directional AES-256 keys and 4-byte nonce prefixes.

Encrypted packets contain a 1-byte version, 8-byte sequence, and AES-GCM ciphertext/tag. Nonces combine the direction-specific prefix with the sequence. Associated data binds transcript hash, direction, and sequence. Receivers accept only the exact next sequence; failed authentication does not consume a sequence. Maximum encrypted packet size is 24 KiB.

Secret arrays are cleared best-effort after use and on session close. Provider-owned copies may remain until garbage collection; this is not hardware-isolated secret storage.

## Implemented

- Ed25519-authenticated v2 transcript and fixed-width binary codec.
- Signed creation timestamp and expiry/future-skew checks on both peers.
- Caller-injected monotonicity-checking time policy.
- Replay-guard retention is an explicit contract and checked against the active freshness window before replay claims.
- Fresh X25519, HKDF-SHA-256, directional AES-256-GCM.
- Strict packet sequencing and bounded process-local replay guard.
- JVM tests for freshness boundaries, clock rollback, timestamp tampering, framing, trust rejection, replay, tampering, and payload limits.

## Not implemented

- Native Android identity-provider adapter or Android provider/device compatibility validation.
- Nearby connection lifecycle integration.
- Durable replay state or rollback-resistant time anchor across process restarts.
- Handshake cancellation/timeouts, key confirmation, or rekey policy.
- Message storage, receipts, direct-message UI, or iOS crypto/transport adapter.

Until native integration and physical-device tests pass, the running app relies only on Google Play services Nearby link encryption. Do not claim Vanguard currently provides end-to-end encrypted peer messaging.
