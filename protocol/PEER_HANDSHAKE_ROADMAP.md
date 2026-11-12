# Peer-session implementation status

- [x] Define a four-message Ed25519-authenticated peer handshake state machine.
- [x] Bind both ephemeral X25519 public keys and fresh nonces into a transcript hash.
- [x] Require fail-closed author trust for both peers.
- [x] Require responder FINISH verification and initiator ACK verification before established state.
- [x] Keep session-key derivation behind an opaque native-provider contract.
- [ ] Implement native X25519 ephemeral key custody, all-zero-secret rejection, and HKDF-SHA-256.
- [ ] Implement native directional AEAD frame encryption, counters, and replay rejection.
- [ ] Integrate handshake state with Nearby connection lifecycle and teardown.
- [ ] Add handshake timeout, cancellation, reconnect, and resource-exhaustion controls.
- [ ] Add native crypto known-answer vectors and cross-platform test vectors.
- [ ] Validate authenticated sessions and adversarial cases on two physical Android devices.
