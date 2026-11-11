# Vanguard architecture decisions

Status: accepted for the application foundation  
Date: 2026-11-11

## Decision 1 — React Native with Expo Development Builds

The user-facing application will use React Native and TypeScript, managed through Expo Development Builds. Expo Go is not the deployment target because Vanguard requires custom native modules and radio access.

The initial target is Android. iOS remains a separate transport implementation, not an assumption that Android Nearby Connections APIs work cross-platform.

## Decision 2 — SDK baseline

Use Expo SDK 58, React Native 0.88, and React 19.3. Pin SDK package versions to the SDK 58 line and run Expo Doctor in CI. Native dependencies must be tested against the selected SDK before adoption.

## Decision 3 — Protocol ownership

The existing Kotlin/JVM protocol core remains the reference implementation for protocol v1. The TypeScript application must not independently invent a second signature encoding. Cross-language test vectors are required before any TypeScript or Swift implementation is allowed to sign protocol events.

The signed envelope is immutable. Hop count, relay path, peer delivery receipts, and retry metadata are mutable transport state and must remain outside the signed envelope.

## Decision 4 — Local persistence

Use expo-sqlite with SQLCipher enabled through its config plugin. Generate a random 256-bit database key and store it in expo-secure-store, which uses Android Keystore-backed encrypted preferences and iOS Keychain. The database must be opened with the key before any schema query.

This protects the local database at rest, but it does not replace device-key custody. Private signing keys must be generated and held by a dedicated native key provider; they must never be exported into JavaScript memory or stored in SQLite/SecureStore as raw private-key bytes.

## Decision 5 — Signature verification boundary

The event repository accepts an injected SignatureVerifier and refuses to persist an event until verification succeeds. A production verifier must be backed by the native protocol/key layer. A missing verifier is an integration gap, not a reason to accept unverified events.

## Decision 6 — Nearby transport boundary

The application depends on a transport interface. Android will use Google Nearby Connections through a native module after a real-device compatibility spike. Do not make the application depend directly on an immature React Native wrapper. A transport implementation must handle permission denial, radio disabled state, disconnects, payload limits, and process lifecycle.

## Decision 7 — Sync semantics

Events remain pending until the Supabase gateway returns an explicit per-event acknowledgement. A request timeout or partial response must not mark an entire batch as synced. Server confirmation is separate from local verification and peer relay acceptance.

## Explicit non-goals for this milestone

- No passkey used as the generic event-signing key. Passkeys authenticate to a relying party; they are not the app's arbitrary offline signing API.
- No assumption that Android Keystore supports Ed25519 hardware-backed keys on every device.
- No assumption that a valid signature proves campus membership.
- No global offline rate-limit guarantee.
- No guaranteed 3-second/20-second background radio schedule.
- No production claims for enrollment, revocation, encrypted peer sessions, Supabase sync, or PlugScore until those flows exist and pass device/server tests.
