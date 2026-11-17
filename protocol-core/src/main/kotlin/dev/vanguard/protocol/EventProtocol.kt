package dev.vanguard.protocol

class EventProtocol(
    private val signer: EventSigner,
    private val verifier: EventSignatureVerifier
) {
    fun create(
        type: String,
        createdAtEpochMs: Long,
        payloadCanonicalJson: String,
        expiresAtEpochMs: Long? = null
    ): EventEnvelope {
        val unsigned = UnsignedEvent(
            version = ProtocolVersion.CURRENT,
            type = type,
            authorPublicKey = signer.encodedPublicKey,
            createdAtEpochMs = createdAtEpochMs,
            expiresAtEpochMs = expiresAtEpochMs,
            payloadCanonicalJson = payloadCanonicalJson
        )
        val bytes = CanonicalEventCodec.unsignedBytes(unsigned)
        return EventEnvelope(
            version = unsigned.version,
            id = Hashing.sha256Url(bytes),
            type = unsigned.type,
            authorPublicKey = unsigned.authorPublicKey,
            createdAtEpochMs = unsigned.createdAtEpochMs,
            expiresAtEpochMs = unsigned.expiresAtEpochMs,
            payloadCanonicalJson = unsigned.payloadCanonicalJson,
            signature = Base64Url.encode(signer.sign(bytes))
        )
    }

    fun verify(event: EventEnvelope, nowEpochMs: Long? = null): Boolean {
        if (event.version != ProtocolVersion.CURRENT) {
            throw ProtocolException.UnsupportedVersion
        }
        val unsigned = UnsignedEvent(
            event.version,
            event.type,
            event.authorPublicKey,
            event.createdAtEpochMs,
            event.expiresAtEpochMs,
            event.payloadCanonicalJson
        )
        val bytes = CanonicalEventCodec.unsignedBytes(unsigned)
        if (Hashing.sha256Url(bytes) != event.id) throw ProtocolException.InvalidEventId
        if (event.expiresAtEpochMs != null && nowEpochMs != null &&
            nowEpochMs >= event.expiresAtEpochMs
        ) {
            throw ProtocolException.ExpiredEvent
        }
        val signatureBytes = try {
            Base64Url.decode(event.signature)
        } catch (_: IllegalArgumentException) {
            throw ProtocolException.InvalidSignature
        }
        if (!verifier.verify(event.authorPublicKey, bytes, signatureBytes)) {
            throw ProtocolException.InvalidSignature
        }
        return true
    }
}
