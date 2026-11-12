# Authenticated peer-session handshake

The TypeScript state machine in src/mesh/peer-handshake.ts defines a four-message authenticated exchange. It is not yet wired into Nearby callbacks and is not a production cryptographic transport by itself.

## Exchange

1. HELLO (initiator → responder): session ID from 16 random bytes, Ed25519 identity key, fresh X25519 ephemeral public key, 32-byte nonce, and a domain-separated Ed25519 signature.
2. RESPONSE (responder → initiator): same session ID, hash of the complete HELLO, responder identity key, fresh X25519 ephemeral public key, 32-byte nonce, and a domain-separated Ed25519 signature.
3. FINISH (initiator → responder): Ed25519 signature over the session ID and transcript hash.
4. ACK (responder → initiator): Ed25519 signature over the same session ID and transcript hash.

The transcript binds the signed initiator HELLO and responder RESPONSE fields. The responder becomes established only after verifying FINISH and producing ACK. The initiator becomes established only after verifying ACK. Application data must not be sent before local established state.

## Key derivation contract

The native provider must generate fresh X25519 keys for every handshake, reject an all-zero shared secret, and derive independent directional traffic keys with HKDF-SHA-256. Use the transcript hash as salt and VANGUARD_PEER_SESSION_KEYS_V1 as the info domain. Keep ephemeral private keys and traffic keys native; JavaScript receives only opaque handles. Authenticated encryption must enforce unique directional nonces and strict replay/counter checks. Erase keys on failure, disconnect, timeout, and explicit disposal.

## Trust boundary and limitations

Nearby authentication digits authenticate transport negotiation only. Both Ed25519 identities must pass the active fail-closed campus author-trust policy. A signature proves control of a key, not the human or campus membership.

The current Android identity module does not implement X25519, HKDF, or authenticated session framing. This state machine accepts an explicit crypto-provider contract; it is not integrated into Nearby lifecycle or event ingress. No production security claim is permitted until native derivation, AEAD framing, replay handling, timeout/teardown, and adversarial two-device tests are complete.
