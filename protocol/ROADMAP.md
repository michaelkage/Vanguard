# Vanguard roadmap

## Milestone 1 — protocol core
- [x] Define protocol v1 event envelope
- [x] Define deterministic unsigned-envelope encoding
- [x] Add Ed25519 reference signing and verification
- [x] Add SHA-256 event IDs and expiry checks
- [x] Add event-store and relay-queue abstractions
- [x] Add focused unit tests
- [ ] Confirm CI has completed successfully
- [ ] Publish cross-language test vectors

## Milestone 2 — Android foundation
- [x] Add Android library module, JDK 17 toolchain, and Android API policy (min 23 / compile 35)
- [x] Add Room event persistence
- [x] Add transactional event acceptance plus durable relay queue insertion
- [x] Add bounded relay batches, acknowledgement, and retry deferral
- [ ] Add Android-backed signing-key custody after validating provider/API support
- [ ] Add trust/revocation snapshot persistence and explicit freshness state
- [ ] Add Android device/instrumentation tests and schema migration tests

## Milestone 3 — two-device exchange
- [ ] BLE discovery and bounded control messages
- [ ] Authenticated session establishment independent of BLE pairing
- [ ] Event transfer, verification, acknowledgements, and retry handling

## Milestone 4 — store-carry-forward
- [ ] Relay receipts outside signed events
- [ ] Hop limits, TTL, quotas, and deduplication across three devices
- [ ] Clear local / received / relayed / server-confirmed delivery states

## Milestone 5 — gateway and campus features
- [ ] Supabase ingestion with server-side signature and policy validation
- [ ] Key enrollment, rotation, revocation, and campus membership
- [ ] Messaging and attributable marketplace vouches
- [ ] Server-computed PlugScore; offline values remain provisional

## Non-negotiable design rules
- Never mutate author-signed event contents during relay.
- Never equate a valid key signature with verified real-world identity.
- Never accept an event into the verified store before signature and protocol validation.
- Never claim offline revocation freshness that the device does not possess.
- Never let clients write authoritative PlugScore totals.
