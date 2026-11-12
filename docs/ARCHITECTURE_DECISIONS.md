# Vanguard architecture decisions

Status: accepted for the application foundation  
Date: 2026-11-11

## Decision 1 — React Native with Expo Development Builds

The user-facing application will use React Native and TypeScript, managed through Expo Development Builds. Expo Go is not the deployment target because Vanguard requires custom native modules and radio access.

The initial target is Android. iOS remains a separate transport implementation, not an assumption that Android Nearby Connections APIs work cross-platform.

## Decision 2 — SDK baseline

Use Expo SDK 58, React Native 0.88, and React 19.3. Pin SDK package versions to the SDK 58 line and run Expo dependency validation in CI. Native dependencies must be tested against the selected SDK before adoption.

## Decision 3 — Protocol ownership

The existing Kotlin/JVM protocol core remains the reference implementation for protocol v1. The TypeScript application must not independently invent a second signature encoding. Cross-language test vectors are required before any TypeScript or Swift implementation is allowed to sign protocol events.

The signed envelope is immutable. Hop count, relay path, peer delivery receipts, and retry metadata are mutable transport state and must remain outside the signed envelope.

## Decision 4 — Local persistence

Use expo-sqlite with SQLCipher enabled through its config plugin. Generate a random 256-bit database key and store it in expo-secure-store. The database must fail closed if SQLCipher is not present in the native binary. Set the key before any schema query.

This protects the local database at rest, but it does not replace device-key custody.

## Decision 5 — Android signing-key custody

The Android identity module generates Ed25519 key pairs with Bouncy Castle. The private PKCS#8 bytes are encrypted at rest using AES-256-GCM with a non-exportable Android Keystore wrapping key. The public key is stored with the encrypted record and authenticated as AES-GCM additional data.

The private key is decrypted only inside the native module for the duration of a signing operation and is never returned to JavaScript. This is **not** a hardware-backed Ed25519 key: Android Keystore does not document a portable Ed25519 key-generation/signing contract across supported devices. The AES wrapping key may be hardware-backed depending on device capabilities, but Vanguard does not yet attest or report that property.

The module does not yet require biometric authentication for signing. Biometric gating must be added as an explicit user-authentication flow rather than being implied by SecureStore or Android Keystore use.

A missing wrapping key with an existing identity record is treated as an unrecoverable local key-custody error. The app must not silently create a replacement identity and pretend it is the same identity.

## Decision 6 — Signature verification boundary

The event repository accepts an injected SignatureVerifier and refuses to persist an event until verification succeeds. A production verifier must be backed by the native protocol/key layer. A missing verifier is an integration gap, not a reason to accept unverified events.

## Decision 7 — Android Nearby transport

Android uses Google Play services Nearby Connections 19.5.1 through a local Expo Kotlin module and a TypeScript transport adapter. The transport uses `Strategy.P2P_CLUSTER` for many-to-many campus discovery and exchange.

The module supports advertising, discovery, explicit incoming connection acceptance/rejection, outgoing connection requests, byte-payload send/receive, transfer status events, and disconnect/stop. Vanguard limits each transport packet to 24 KiB, below the protocol envelope's 24 KiB maximum; application framing must still ensure the serialized envelope fits the limit.

The module checks runtime permissions by API level: coarse location on API 23–28, coarse plus fine location on API 29–32 (requested together on Android 12L), Bluetooth scan/connect/advertise on API 31–32, and Bluetooth scan/connect/advertise plus `NEARBY_WIFI_DEVICES` from API 33. The manifest caps legacy location declarations at API 32 and declares `NEARBY_WIFI_DEVICES` from API 33. Permission denial is surfaced; the transport does not silently bypass it.

Nearby Connections encrypts the transport link and exposes its short authentication digits. Neither fact proves that the remote endpoint controls a campus-enrolled Vanguard identity key. The application verifies the Vanguard signature and applies an injected author-trust policy before storing any received event. The mesh ingress bounds packet size and concurrent processing, and the receiver—not the sender—sets the maximum accepted hop count. The hop count itself is unauthenticated mutable metadata, so a malicious relay can reset it; authenticated relay provenance is required before claiming adversarial hop-limit enforcement. The author-trust policy must fail closed for unknown keys, revoked keys, and stale revocation snapshots. The authentication digits are exposed so a future trust UI can let users compare them.

The `NearbyMeshSession` service owns listener registration, verified ingress attachment, advertising/discovery startup, explicit connection approval/rejection, and teardown. Startup awaits both radio operations and rolls back listeners and transport if either fails. The Android composition factory supplies the native Ed25519 verifier but requires an injected author-trust policy; there is deliberately no permissive default while enrollment and revocation infrastructure is absent. Android background discovery remains opportunistic.

This implementation is Android-only and requires compatible Google Play services. iOS will use a separate transport adapter; cross-platform Android-to-iOS interoperation is not claimed. The code still requires Android compilation and physical-device validation.

## Decision 8 — Sync semantics

Events remain pending until the Supabase gateway returns an explicit per-event acknowledgement. A request timeout or partial response must not mark an entire batch as synced. Server confirmation is separate from local verification and peer relay acceptance.

## Explicit non-goals for this milestone

- No passkey used as the generic event-signing key. Passkeys authenticate to a relying party; they are not the app's arbitrary offline signing API.
- No claim that the Ed25519 private key itself is hardware-backed.
- No claim that key protection is biometric-gated in the current module.
- No assumption that a valid signature proves campus membership.
- No global offline rate-limit guarantee.
- No guaranteed 3-second/20-second background radio schedule.
- No production claims for enrollment, revocation, encrypted peer sessions, Supabase sync, or PlugScore until those flows exist and pass device/server tests.


## Decision 9 — Campus author registry snapshots

Campus trust is established by a server-authorized device-key registry, not by the event signature alone. The client accepts only versioned Ed25519-signed snapshots whose signature verifies against a public key pinned by the application. The signature covers a domain-separated canonical representation of the campus ID, monotonic sequence, issue/expiry times, and a uniquely sorted list of public keys with active, suspended, or revoked status.

The client rejects unknown campuses, malformed or unsorted entries, invalid signatures, expired or stale snapshots, materially future-issued snapshots, sequence rollback, and same-sequence content changes. A cached snapshot is re-verified after process restart and is no longer trusted after its freshness window expires. Snapshot persistence uses the SQLCipher database and is monotonic per campus. The registry requires an injected rollback-aware clock and checks that its timestamp agrees with the event-ingress timestamp; a raw wall clock is not a strong time source against a device owner who can change system time.

This is the client-side verification and cache boundary only. It does not implement campus enrollment, server-side key binding, registry issuance, key rotation APIs, or revocation publication. Those remain backend work. The server signing key must be provisioned/pinned by the application; a key supplied by the snapshot itself is never trusted. Until the app has a rollback-resistant time source across reboots, snapshot freshness is bounded by the caller-supplied clock and must not be described as tamper-proof.


## Decision 10 — Authenticated ephemeral peer sessions

The protocol reference uses Ed25519 device identities only to authenticate handshake transcripts. Each session generates fresh X25519 ephemeral key pairs; Ed25519 signing keys are never reused for key agreement. The initiator signs a versioned v2 hello containing a signed creation timestamp, random session ID, 256-bit nonce, ephemeral X25519 public key, and identity public key. Both peers enforce a caller-supplied rollback-detecting epoch-time policy; default maximum hello age is 120 seconds and maximum future skew is 30 seconds. The responder validates freshness before consuming replay state, and the initiator rechecks freshness when completing the handshake. The v2 wire format and signature domains are incompatible with v1. The responder verifies the signature and fail-closed author trust, atomically claims the session ID/initiator nonce through an injected replay guard whose declared retention is checked against the active freshness window, and signs a response that binds the complete initiator hello, both nonces, both ephemeral keys, and both identity keys. The initiator verifies the responder signature and author trust before deriving traffic keys.

Both sides derive independent initiator-to-responder and responder-to-initiator AES-256-GCM keys and nonce prefixes using HKDF-SHA-256 with the transcript hash as salt and a versioned domain-separated context. Encrypted packets bind the transcript hash, direction, and monotonically increasing sequence number as AEAD associated data. Receivers accept only the exact next sequence number; replayed and out-of-order packets are rejected. Authentication failures do not consume a receive sequence. The packet header, GCM tag, and plaintext are bounded by the existing 24 KiB Nearby payload ceiling. Session close zeroes the in-memory traffic-key and nonce-prefix arrays.

This is a Kotlin/JVM reference implementation with unit tests, not a production Android integration. The caller must supply a trusted identity verifier, fail-closed campus author-trust policy, and atomic replay guard. The reference now includes a fixed-width, versioned binary codec for bounded hello and response frames. A bounded process-local replay guard with monotonic expiry and fail-closed capacity handling is included; its declared retention is enforced against the configured maximum hello age plus future skew, but it does not survive process death. Durable replay protection, a rollback-resistant time anchor across reboot, handshake timeout/rekey policy, native Ed25519 adapter, and integration with Nearby connection state remain unimplemented. The reference has not been validated across Android providers or physical devices. Until those integration and device tests pass, existing Nearby link encryption remains the only active transport encryption and must not be described as Vanguard end-to-end encryption.
