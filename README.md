# Vanguard

Vanguard is a local-first, peer-to-peer identity and communication system for campus environments where mobile internet is unreliable or unavailable.

The product goal is store-carry-forward communication: nearby devices exchange signed events locally, retain them safely, and synchronize with the authoritative backend when connectivity returns.

## Field manual

The interactive engineering field manual is published at [michaelkage.github.io/Vanguard](https://michaelkage.github.io/Vanguard/). It includes a browser-only signed-event packet lab, architecture map, operational constraints, and live GitHub repository/release metadata. The packet lab is a simulation: it does not persist to the app database, use device radios, or contact the backend.

Validate the manual locally with `node --test scripts/site.node.mjs`.

## Application stack

- React Native + TypeScript on Expo Development Builds.
- Expo SDK 58 / React Native 0.88 / React 19.3.
- Expo SQLite with SQLCipher for encrypted local event storage.
- Expo SecureStore for the SQLCipher database key.
- A 50 MiB logical event-store budget; expired events and oldest server-confirmed events are pruned before rejecting new storage. Pending/unconfirmed events are never silently discarded. SQLite page files and WAL overhead mean this is not a hard physical disk-usage ceiling.
- Native Android Ed25519 identity module; private PKCS#8 bytes are AES-GCM encrypted at rest with an Android Keystore-managed wrapping key.
- Native Android Google Nearby Connections 19.5.1 behind a TypeScript transport adapter. It supports P2P-cluster advertising/discovery, explicit connection acceptance, authentication digits, and bounded byte-payload transfer (24 KiB Vanguard packet ceiling).
- Supabase Postgres and Edge Functions as the authoritative synchronization and policy boundary.

## Repository structure

- `src/protocol` — TypeScript transport-envelope validation and relay policy. Kotlin remains the protocol v1 reference until cross-language vectors prove parity.
- `src/storage` — SQLCipher database bootstrap, verified-event/outbox repository, and monotonic campus registry snapshot cache.
- `src/mesh` — Android transport adapter, lifecycle-managed advertising/discovery and explicit connection approval, bounded relay-packet framing, native Ed25519 verification adapter, and fail-closed verified ingress.
- `src/identity` — native signing composition and fail-closed verification of pinned-server-signed campus author registry snapshots.
- `modules/vanguard-identity` — local Expo module for native Android Ed25519 key generation, signing, verification, and deletion.
- `modules/vanguard-nearby` — local Expo module for Android peer discovery, connection lifecycle, and bounded byte transport.
- `protocol-core` — Kotlin/JVM event protocol reference plus an authenticated ephemeral peer-session reference (Ed25519 transcript authentication, X25519 agreement, HKDF-SHA-256, directional AES-256-GCM, and strict replay/order counters). The peer-session reference is not yet connected to the Android transport.
- `android-runtime` — existing Room storage foundation, retained during the migration for comparison and parity testing.
- `protocol` — protocol contract and roadmap.
- `docs/ARCHITECTURE_DECISIONS.md` — accepted engineering decisions and explicit security boundaries.

## Requirements

- Node.js 22.13 or newer.
- JDK 17 and Android SDK for Android builds.
- A physical Android device for Nearby Connections, permissions, radio-state, background execution, and Keystore validation.

## Commands

```bash
npm install
npx expo install --fix
npm run typecheck
npm test
npm run doctor
npx expo prebuild --platform android
npm run android
```

The app requires a development build. Expo Go is not sufficient for custom native functionality. `NearbyMeshSession` owns advertising, discovery, verified ingress, connection approval, and teardown. Incoming connection requests are never accepted automatically; callers must explicitly accept or reject them. The generic Android session factory requires an injected author-trust policy and intentionally does not supply a permissive default. `createAndroidCampusMeshSession` composes native Ed25519 event verification, a campus registry policy, and the SQLCipher-backed snapshot cache; the campus ID, pinned server public key, maximum snapshot age, and rollback-aware clock must be supplied by app configuration. The caller must fetch and install a valid signed snapshot before any author is trusted.

## Security status

The SQLCipher database is encrypted at rest using a random key held by SecureStore. The identity module keeps Ed25519 private-key material out of JavaScript and encrypts it at rest with AES-256-GCM under an Android Keystore key. During signing, the private key is decrypted in native process memory. This is not equivalent to a non-exportable hardware-backed Ed25519 key, and the current module does not yet enforce biometric authentication.

A valid signature proves control of a key, not real-world identity or campus enrollment. Passkeys are reserved for account authentication; they are not treated as general-purpose offline event-signing keys. Relay metadata is mutable and is never included in the author's signed envelope. Offline vouches remain provisional until the backend validates them.

## Not yet production-ready

The native Android identity and Nearby modules compile as part of the generated Expo Android application in CI, but neither has been validated on physical devices. The session controller coordinates radio startup and cleanup and exposes explicit connection decisions; Android background execution remains opportunistic, not continuous. The Nearby link is encrypted by Google Play services, but it does not establish author identity. A Kotlin/JVM authenticated peer-session v2 reference specifies signed ephemeral X25519 handshakes, directional AES-GCM traffic keys, signed creation timestamps, and caller-supplied expiry/clock-rollback policy; it is not yet wired into the Expo identity module or Nearby session lifecycle. Mesh ingress now validates a bounded relay frame, verifies the event signature, applies an injected fail-closed author-trust policy, and only then calls the durable event repository. The receiver enforces its own hop ceiling rather than accepting a peer-supplied maximum. Hop count itself remains unauthenticated relay metadata, so a malicious peer can reset it; authenticated relay provenance is still required for adversarial hop-limit enforcement. Biometric authorization, native integration for the signed peer-session reference, server-side campus enrollment and key-registry issuance/rotation/revocation, Supabase ingestion and per-event acknowledgements, push notifications, authoritative PlugScore policy, and real-device relay acceptance tests remain to be implemented. Client-side registry snapshot verification is implemented, but it cannot trust any campus key until a real backend issues a valid snapshot under the pinned server key. Android Nearby Connections requires Google Play services; iOS transport is not implemented.

Do not use this foundation for payments, emergency services, or high-value authorization.

See `protocol/PROTOCOL.md`, `protocol/AUTHOR_REGISTRY.md`, `protocol/PEER_SESSION.md`, `protocol/ROADMAP.md`, and `docs/ARCHITECTURE_DECISIONS.md`.
