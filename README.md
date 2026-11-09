# Vanguard

Local-first, peer-to-peer mesh identity and communication for campus environments with unreliable or unavailable internet.

## Current milestones

### Protocol core
A transport-independent Kotlin/JVM core defines immutable signed events, verification, event IDs, duplicate-safe storage interfaces, and a relay queue abstraction.

### Android storage foundation
The `:android-runtime` library adds a Room-backed event store and durable store-carry-forward relay queue. It is deliberately separate from the protocol module.

Included Android storage behavior:
- Persist the complete author-signed event envelope without rewriting its contents.
- Atomically insert a verified event and its relay queue entry.
- Deduplicate events by immutable event ID.
- Read bounded relay batches and acknowledge or defer individual events.
- Persist retry count, next-attempt time, and the last bounded error string.

**Important:** callers must verify an incoming event with `EventProtocol` before passing it to `RoomEventRepository.storeVerifiedAndQueue`. The storage layer does not authenticate users, verify signatures, establish campus membership, or determine revocation status.

## Modules

- `:protocol-core` — transport-independent protocol v1, JVM reference Ed25519 signer/verifier, event validation and in-memory adapters.
- `:android-runtime` — Android library with Room persistence and a durable relay queue.

## Build

Requirements: JDK 17, Gradle 8.10.2, and Android SDK Platform 35 for the Android module.

```bash
gradle test
gradle :android-runtime:assembleDebug
```

## Not implemented yet

Android Keystore-backed signing, a production Android key provider, Android application/UI shell, BLE/Wi-Fi Direct transport, authenticated peer sessions, enrollment and revocation, trust-snapshot freshness, Supabase synchronization, and PlugScore integration are still future work.

## Security boundaries

A valid signature proves control of a private key, not a student's civil identity or campus membership. Offline revocation knowledge is necessarily stale; the application must expose the age of its last trusted revocation snapshot. Offline marketplace scores must be labelled provisional until server validation.

The JVM key implementation is for protocol development and tests. The Android storage module does not yet provide production key custody. Do not use this prototype for payments, emergency services, or high-value authorization.

See [protocol/PROTOCOL.md](protocol/PROTOCOL.md) for the wire contract and [protocol/ROADMAP.md](protocol/ROADMAP.md) for the next steps.
