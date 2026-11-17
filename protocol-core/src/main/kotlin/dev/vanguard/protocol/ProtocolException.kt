package dev.vanguard.protocol

sealed class ProtocolException(message: String) : IllegalArgumentException(message) {
    data object UnsupportedVersion : ProtocolException("Unsupported protocol version")
    data object InvalidEventId : ProtocolException("Event ID does not match event contents")
    data object InvalidSignature : ProtocolException("Event signature is invalid")
    data object ExpiredEvent : ProtocolException("Event has expired")
    data object InvalidField : ProtocolException("Event contains an invalid field")
}
