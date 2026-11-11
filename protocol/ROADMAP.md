# Vanguard roadmap

## Milestone 1 — protocol v1 reference core
- [x] Define immutable protocol v1 event envelope
- [x] Define deterministic unsigned-envelope encoding
- [x] Add Ed25519 reference signing and verification
- [x] Add SHA-256 event IDs and expiry checks
- [x] Add event-store and relay-queue abstractions
- [x] Add focused Kotlin/JVM unit tests
- [ ] Publish Kotlin/TypeScript/Swift cross-language test vectors
- [ ] Strictly parse and canonicalize event-type payloads

## Milestone 2 — Android persistence reference
- [x] Add Android library module, JDK 17 toolchain, and Android API policy
- [x] Add Room event persistence
- [x] Add transactional event acceptance plus durable relay queue insertion
- [x] Add bounded relay batches and retry deferral
- [ ] Add Room schema migration and Android instrumentation tests
- [ ] Keep Room as a migration/reference implementation until Expo parity is proven

## Milestone 3 — Expo application foundation
- [x] Create Expo SDK 58 / React Native 0.88 / TypeScript application
- [x] Add Expo Development Build configuration
- [x] Enable SQLCipher for Expo SQLite
- [x] Protect the random database key with Expo SecureStore
- [x] Add strict v1 event-envelope shape validation
- [x] Add relay policy, hop-depth metadata, and peer deduplication
- [x] Add durable local event/outbox repository
- [x] Enforce a 50 MiB logical event-store budget without silently deleting unconfirmed events
- [x] Add TypeScript unit tests and CI checks
- [ ] Commit npm lockfile and complete clean-install verification on a developer workstation
- [ ] Add integration tests against a real SQLCipher-enabled development build

## Milestone 4 — Android native identity and transport
- [ ] Implement native Android device-key provider without exporting private keys to JavaScript
- [ ] Validate Ed25519 provider availability on supported Android versions; define an explicit protocol migration if compatibility requires another algorithm
- [ ] Implement Google Nearby Connections behind the TypeScript transport interface
- [ ] Handle permission denial, disabled radios, reconnects, lifecycle, and bounded payloads
- [ ] Validate two physical Android devices and Android-to-iOS interoperability policy
- [ ] Add authenticated peer sessions and end-to-end encrypted direct messages

## Milestone 5 — store-carry-forward acceptance
- [ ] Verify event signatures before persistence on every ingress path
- [ ] Test A-to-B-to-C relay after A leaves range
- [ ] Test duplicate suppression and peer delivery receipts
- [ ] Test expiry, hop limits, storage pressure, retry, and process restart
- [ ] Distinguish locally created, locally verified, peer-relayed, and server-confirmed states

## Milestone 6 — Supabase gateway and campus identity
- [ ] Implement authenticated enrollment and campus membership binding
- [ ] Add device-key registry, rotation, revocation, and revocation snapshot freshness
- [ ] Implement Edge Function ingestion with strict schema and server-side signature verification
- [ ] Make event insertion idempotent and return per-event acknowledgements
- [ ] Add encrypted message relay and privacy-safe push notifications
- [ ] Add server-computed PlugScore projections and provisional offline vouches
- [ ] Add server-side account-wide abuse controls and audit records

## Non-negotiable design rules
- Never mutate author-signed event contents during relay.
- Never place hop count, relay path, or receipts inside the author's signed envelope.
- Never equate a valid key signature with verified real-world identity or campus membership.
- Never accept an event into the verified store before signature and protocol validation.
- Never claim offline revocation freshness that the device does not possess.
- Never let clients write authoritative PlugScore totals.
- Never mark cloud sync complete without explicit per-event server acknowledgement.
- Never silently discard unconfirmed events to satisfy a storage budget.
