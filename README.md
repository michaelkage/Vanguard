# Vanguard

Vanguard is a local-first, peer-to-peer identity and communication system for campus environments where mobile internet is unreliable or unavailable.

The product goal is store-carry-forward communication: nearby devices exchange signed events locally, retain them safely, and synchronize with the authoritative backend when connectivity returns.

## Application stack

- React Native + TypeScript on Expo Development Builds.
- Expo SDK 58 / React Native 0.88 / React 19.3.
- Expo SQLite with SQLCipher for encrypted local event storage.
- Expo SecureStore for the SQLCipher database key.
- A 50 MiB logical event-payload budget; expired events and oldest server-confirmed events are pruned before rejecting new storage. Pending/unconfirmed events are never silently discarded. SQLite page files and WAL overhead mean this is not a hard physical disk-usage ceiling.
- Native Android key custody and Google Nearby Connections behind application interfaces.
- Supabase Postgres and Edge Functions as the authoritative synchronization and policy boundary.

## Repository structure

- src/protocol — TypeScript transport-envelope validation and relay policy. Kotlin remains the protocol v1 reference until cross-language vectors prove parity.
- src/storage — SQLCipher database bootstrap and verified-event/outbox repository.
- src/mesh — transport interface; native Android transport is a separate implementation milestone.
- protocol-core — existing Kotlin/JVM protocol reference and tests.
- android-runtime — existing Room storage foundation, retained during the migration for comparison and parity testing.
- protocol — protocol contract and roadmap.
- docs/ARCHITECTURE_DECISIONS.md — accepted engineering decisions and explicit security boundaries.

## Requirements

- Node.js 22.13 or newer.
- JDK 17 and Android SDK for the retained Kotlin/Android modules.
- A physical Android device for Nearby Connections, permissions, radio-state, background execution, and Keystore validation.

## Commands

```bash
npm install
npx expo install --fix
npm run typecheck
npm test
npm run doctor
npm run android
```

The app requires a development build. Expo Go is not sufficient for custom native functionality.

## Security status

The SQLCipher database is encrypted at rest using a random key held by SecureStore. The private event-signing key is not implemented in the JavaScript layer. The event repository fails closed unless a cryptographic verifier is supplied.

A valid signature proves control of a key, not real-world identity or campus enrollment. Passkeys are reserved for account authentication; they are not treated as general-purpose offline event-signing keys. Relay metadata is mutable and is never included in the author's signed envelope. Offline vouches remain provisional until the backend validates them.

## Not yet production-ready

Native Android Keystore signing, the Android Nearby Connections implementation, enrollment and key revocation, authenticated/encrypted peer sessions, Supabase ingestion and per-event acknowledgements, push notifications, authoritative PlugScore policy, and real-device acceptance tests remain to be implemented.

Do not use this foundation for payments, emergency services, or high-value authorization.

See protocol/PROTOCOL.md, protocol/ROADMAP.md, and docs/ARCHITECTURE_DECISIONS.md.
