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
- [x] Enable SQLCipher for Expo SQLite and fail closed if SQLCipher is missing
- [x] Protect the random database key with Expo SecureStore
- [x] Add strict v1 event-envelope shape validation
- [x] Add relay policy, hop-depth metadata, and peer deduplication
- [x] Add durable local event/outbox repository
- [x] Enforce a 50 MiB logical event-store budget without silently deleting unconfirmed events
- [x] Add TypeScript unit tests and CI checks
- [ ] Commit npm lockfile and complete clean-install verification on a developer workstation
- [ ] Add integration tests against a real SQLCipher-enabled development build

## Milestone 4 — Android native identity and transport
- [x] Add local Expo native module for Ed25519 identity creation, signing, verification, and deletion
- [x] Add TypeScript protocol verifier adapter backed by native Ed25519 verification
- [x] Compose native verification with fail-closed Nearby event ingress
- [x] Add lifecycle-managed Nearby session orchestration with startup rollback and idempotent teardown
- [x] Require explicit incoming connection approval/rejection in the session API
- [x] Keep private-key material out of JavaScript and encrypt it at rest with an Android Keystore AES-GCM wrapping key
- [x] Compile the generated Expo Android application and both local native modules in CI
- [ ] Validate identity creation, signing, verification, and key custody on physical Android devices
- [ ] Add biometric authorization for key use
- [ ] Verify Kotlin/TypeScript/native signature bytes against shared protocol test vectors
- [x] Implement native Android Google Nearby Connections behind the TypeScript transport interface
- [x] Add Android Nearby permission declarations and runtime permission checks, including the Android 13 permission boundary
- [x] Add explicit connection acceptance/rejection and authentication-digit callbacks
- [x] Bound Vanguard byte payloads to 24 KiB and expose transfer callbacks
- [x] Add bounded relay packet framing and fail-closed signature/author-policy ingress
- [x] Enforce receiver-owned maximum hop acceptance and bounded concurrent ingress
- [ ] Authenticate relay provenance so malicious peers cannot reset hop depth
- [ ] Handle permission denial UX, disabled radios, reconnects, and lifecycle
- [ ] Validate session startup/shutdown, connection approval, and recovery on physical Android devices
- [ ] Validate two physical Android devices and Android-to-iOS interoperability policy
- [x] Add Kotlin/JVM reference for Ed25519-authenticated ephemeral X25519 peer handshakes
- [x] Derive directional AES-256-GCM traffic keys with HKDF-SHA-256 and transcript binding
- [x] Add strict per-direction packet sequencing, replay rejection, and bounded 24 KiB framing
- [x] Add fixed-width bounded binary codec for v2 hello and response frames
- [x] Sign initiator creation timestamp and enforce expiry/future-skew checks on both peers
- [x] Require caller-injected rollback-detecting handshake time policy
- [x] Enforce replay-guard retention against configured handshake freshness before accepting replay claims
- [ ] Add durable replay protection and rollback-resistant time anchor across process restarts
- [x] Add byte-oriented native Ed25519 signing and verification API without UTF-8 conversion
- [x] Compile shared peer-session protocol core into the Android identity module
- [x] Add explicit Bouncy Castle provider injection for Ed25519/X25519 parsing, generation, and agreement without global provider registration
- [x] Add native identity-provider adapters implementing the protocol signer/verifier interfaces
- [ ] Validate Bouncy Castle X25519 behavior and identity key operations on API 23 and current Android devices
- [ ] Integrate authenticated session state with Android Nearby connection lifecycle
- [x] Add bounded process-local replay guard with monotonic expiry and fail-closed capacity handling
- [ ] Add durable replay guard and handshake lifecycle/timeout policy
- [ ] Validate two-device handshake, rekey, disconnect, and message exchange
- [ ] Integrate end-to-end encrypted direct messages with durable message storage

## Milestone 5 — store-carry-forward acceptance
- [x] Verify event signatures and author-trust policy before persistence on the Nearby ingress path
- [ ] Verify event signatures before persistence on every remaining ingress path
- [ ] Test A-to-B-to-C relay after A leaves range
- [ ] Test duplicate suppression and peer delivery receipts
- [ ] Test expiry, hop limits, storage pressure, retry, and process restart
- [ ] Distinguish locally created, locally verified, peer-relayed, and server-confirmed states

## Milestone 6 — Supabase gateway and campus identity
- [ ] Implement authenticated enrollment and campus membership binding
- [x] Verify pinned-server-signed campus author snapshots and cache them monotonically in SQLCipher in the TypeScript client
- [x] Add native Kotlin v1 snapshot parsing, canonical-message reconstruction, pinned-key Ed25519 verification, and freshness checks
- [ ] Add native durable sequence/equivocation state and compose a native fail-closed author-trust policy
- [ ] Implement the server-side device-key registry, enrollment, rotation, revocation, and snapshot issuance
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
