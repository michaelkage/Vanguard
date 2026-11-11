# Campus author registry snapshot protocol

This document defines the client/server contract for campus membership and Vanguard signing-key trust. It is separate from the signed event envelope.

## Trust model

- A Vanguard event signature proves control of an Ed25519 key; it does not prove campus membership.
- The client trusts a key only when it appears with status `active` in a fresh, valid snapshot for the configured campus.
- The snapshot is signed by a server Ed25519 key pinned in the application. A public key supplied by the snapshot is never used as its own trust root.
- Unknown, suspended, revoked, expired, stale, malformed, or unverifiable keys are rejected.
- The client cache is encrypted by SQLCipher and enforces a monotonically increasing sequence per campus.
- The client must use a rollback-aware clock shared with mesh ingress. A normal wall clock alone cannot provide tamper-proof offline freshness.

## Snapshot wire format

The snapshot has exactly these fields:

```json
{
  "version": 1,
  "campusId": "unilag",
  "sequence": 42,
  "issuedAtEpochMs": 1794400000000,
  "expiresAtEpochMs": 1794486400000,
  "authors": [
    {
      "publicKey": "BASE64URL_X509_SPKI_ED25519",
      "status": "active"
    }
  ],
  "signature": "BASE64URL_ED25519_SIGNATURE"
}
```

Constraints:

- `campusId` is a stable lowercase slug: 1–64 characters from `a-z0-9._-`, beginning with an alphanumeric.
- `sequence` is a positive safe integer and strictly increases for each newly issued campus snapshot.
- `issuedAtEpochMs` and `expiresAtEpochMs` are non-negative safe integers; expiry must be later than issue time.
- Each author public key is the 59-character unpadded base64url encoding of the 44-byte Ed25519 SubjectPublicKeyInfo representation used by Vanguard.
- Each signature is the 86-character unpadded base64url encoding of a 64-byte Ed25519 signature.
- `authors` is strictly ascending by `publicKey`; duplicate keys are forbidden.
- Status is exactly `active`, `suspended`, or `revoked`. A key absent from the snapshot is untrusted.
- The client currently limits snapshots to 100,000 entries and 8 MiB.

## Signature construction

The signature field is excluded from the signed object. The server signs this exact UTF-8 message:

```text
VANGUARD_AUTHOR_REGISTRY_V1\n
```

followed immediately by deterministic canonical JSON of the object containing only:

```json
{
  "version": 1,
  "campusId": "...",
  "sequence": 42,
  "issuedAtEpochMs": 1794400000000,
  "expiresAtEpochMs": 1794486400000,
  "authors": []
}
```

Canonical JSON sorts object keys recursively using JavaScript UTF-16 code-unit ordering and ECMAScript JSON number serialization. Array order is preserved; therefore the author list must already be sorted as specified. This is the current Vanguard canonical JSON contract, not a claim of complete RFC 8785/JCS interoperability. Server implementations must share test vectors with the client before production rollout.

## Enrollment and key lifecycle requirements

The server must not activate a public key merely because an authenticated user submits it.

1. Authenticate the user through the existing campus account system.
2. Check authoritative campus membership and account suspension status.
3. Issue a short-lived, single-use enrollment challenge bound to the authenticated account, campus, and submitted public key.
4. Require proof of possession: the device signs the challenge with its native Ed25519 private key.
5. Bind the verified public key to the account and campus in a server-controlled registry.
6. Publish a new signed snapshot with a higher sequence.
7. On rotation, prove possession of the new key, activate it, and mark the previous key revoked in the same authoritative operation.
8. On account suspension or key revocation, publish the new status in a higher-sequence snapshot. Clients must fail closed when their snapshot exceeds the configured freshness window.

The registry must retain enough history for audit and incident investigation. Client-provided profile metadata, user-editable JWT metadata, device fingerprints, Nearby authentication digits, and event signatures alone are not enrollment proof.

## Gateway requirements

- Registry writes are server-only. Clients cannot directly activate, revoke, or rotate keys through table writes.
- Snapshot reads may be public or authenticated according to the deployment's privacy policy, but the signing private key remains server-side.
- Event ingestion independently verifies event signatures, campus key status, expiry, schema, and idempotency. It does not trust a client's local trust decision.
- Supabase RLS must be enabled on exposed tables. Use a private schema for internal key-binding state where appropriate; never expose a service-role credential to the app.
- Cloud event acknowledgements are per event ID. Clients mark an event confirmed only after the gateway explicitly acknowledges that exact ID.
- PlugScore totals remain server-computed. Offline vouches are provisional until validated by the backend.

## Current implementation boundary

Implemented in the Android client:

- Strict snapshot shape and key-list validation.
- Pinned-server Ed25519 signature verification through the native identity module.
- Freshness and clock-consistency checks.
- Monotonic sequence and same-sequence equivocation rejection.
- SQLCipher persistence and restart-time signature re-verification.
- Fail-closed author trust policy integrated into the campus-aware Android mesh session factory.

Not yet implemented:

- Authenticated enrollment challenge and proof-of-possession endpoint.
- Server-side key registry and signing-key custody.
- Snapshot issuance, distribution, key rotation, and revocation publication.
- Rollback-resistant time anchoring across device reboots.
- Supabase event ingestion, acknowledgements, and PlugScore projection integration.
