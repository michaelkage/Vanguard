# Vanguard

Local-first, peer-to-peer mesh identity and communication for campus environments with unreliable or unavailable internet.

## First milestone: protocol core

This repository begins with a transport-independent Kotlin/JVM core. It defines immutable signed events, verification, event IDs, duplicate-safe storage interfaces, and a relay queue abstraction.

### Included
- Versioned event envelope (protocol v1)
- Deterministic encoding of the signed envelope fields
- SHA-256 event IDs
- Ed25519 signer and verifier interfaces with JVM reference implementations
- Expiry validation
- In-memory event store and relay queue reference adapters
- Unit tests for signature verification, tampering, expiry, and deduplication

### Not included yet
BLE/Wi-Fi discovery and transport, Android UI, Android Keystore integration, Room persistence, enrollment and revocation, encrypted peer sessions, Supabase sync, or PlugScore integration.

## Build
Requirements: JDK 17+ and Gradle 8.7+.

```bash
gradle test
```

## Security boundaries
A valid signature proves control of a private key, not a student's civil identity or campus membership. Offline revocation knowledge is necessarily stale; the application must expose the age of its last trusted revocation snapshot. Offline marketplace scores must be labelled provisional until server validation.

The JVM key implementation is for protocol development and tests. Production Android key custody must use a platform-backed implementation and be tested against the supported Android API/device matrix. Do not use this prototype for payments, emergency services, or high-value authorization.

See [protocol/PROTOCOL.md](protocol/PROTOCOL.md) for the wire contract and [protocol/ROADMAP.md](protocol/ROADMAP.md) for the next steps.
