package dev.vanguard.protocol

import java.security.MessageDigest
import java.util.Base64

object Hashing {
    fun sha256Url(bytes: ByteArray): String =
        Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(MessageDigest.getInstance("SHA-256").digest(bytes))
}
