# Vanguard roadmap

## Milestone 1 — protocol core (current)
- [x] Define protocol v1 event envelope
- [x] Define deterministic unsigned-envelope encoding
- [x] Add Ed25519 reference signing and verification
- [x] Add SHA-256 event IDs and expiry checks
- [x] Add event-store and relay-queue abstractions
- [x] Add focused unit tests
- [ ] Run CI and validate on the target JDK/Gradle environment
- [ ] Publish cross-language test vectors

## Milestone 2 — Android foundation
- Android application shell and supported API-level policy
- Android-backed key custody adapter, with device/provider capability tests
- Room-backed event store and durable outbox
- Explicit trust/revocation snapshot state in the domain model

## Milestone 3 — two-device exchange
- BLE discovery and bounded control messages
- Authenticated session establishment independent of BLE pairing
- Event transfer, verification, acknowledgements, and retry handling

## Milestone 4 — store-carry-forward
- Relay receipts outside signed events
- Hop limits, TTL, quotas, and deduplication across three devices
- Clear local / received / relayed / server-confirmed delivery states

## Milestone 5 — gateway and campus features
- Supabase ingestion with server-side signature and policy validation
- Key enrollment, rotation, revocation, and campus membership
- Messaging and attributable marketplace vouches
- Server-computed PlugScore; offline values remain provisional

## Non-negotiable design rules
- Never mutate author-signed event contents during relay.
- Never equate a valid key signature with verified real-world identity.
- Never claim offline revocation freshness that the device does not possess.
- Never let clients write authoritative PlugScore totals.
