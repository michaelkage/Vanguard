# Vanguard Protocol v1 — initial core contract

## Scope
V1 defines an immutable author-signed event. Transport framing, peer discovery, enrollment, revocation feeds, and server synchronization are outside this initial core.

## Envelope
- `version`: protocol version, currently `1`
- `id`: base64url-no-padding SHA-256 of canonical unsigned event bytes
- `type`: lowercase event type, e.g. `message.created`
- `authorPublicKey`: base64url-no-padding X.509 SubjectPublicKeyInfo Ed25519 public key
- `createdAtEpochMs`: author-declared Unix timestamp in milliseconds
- `expiresAtEpochMs`: optional expiry, later than creation
- `payloadCanonicalJson`: canonical JSON object supplied by the event-type layer
- `signature`: base64url-no-padding Ed25519 signature over canonical unsigned bytes

The ID and signature cover the same unsigned representation, excluding ID and signature.

## Canonical representation
Fields are encoded in this exact order: `version`, `type`, `authorPublicKey`, `createdAtEpochMs`, `expiresAtEpochMs`, `payload`. Strings use JSON escaping and UTF-8. Expiry is an integer or `null`.

This fixed-field encoder is Vanguard v1; it is **not** a claim of full RFC 8785/JCS compliance. Payload JSON must be canonicalized by the event-type layer before it reaches this module. The current core checks object-shaped input but does not parse or canonicalize arbitrary JSON. Cross-language test vectors and a vetted canonical JSON implementation are required before production interoperability.

## Trust semantics
- A valid signature proves control of the corresponding private key, not campus enrollment or real-world identity.
- Enrollment must bind campus identity to device keys through an authenticated process.
- Offline revocation knowledge is limited to the last received snapshot; clients must expose snapshot age.
- Relay receipts are separate metadata and never modify the author-signed envelope.
- Offline marketplace vouches must be labelled provisional until backend policy checks finish.

## Offline semantics
- Timestamps are author claims; device clocks may be wrong.
- Expiry is a local policy check.
- Duplicate IDs are ignored.
- Relays may carry untrusted envelopes, but receivers verify before accepting them into the verified event store.

## Required before production
1. Publish Kotlin, TypeScript, and Swift test vectors.
2. Add strict payload schemas, parser hardening, and payload size limits.
3. Implement enrollment, key rotation, revocation, and stale-snapshot UX.
4. Add authenticated/encrypted peer sessions; BLE proximity is not identity.
5. Add replay, rate, relay-quota, TTL, and hop-limit controls.
6. Add Room persistence and crash-safe outbox processing.
7. Add server-side signature validation and idempotent Supabase ingestion.
