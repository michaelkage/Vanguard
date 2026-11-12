package dev.vanguard.identity

import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/**
 * Native verifier for the server-signed campus author snapshot.
 *
 * The registry signing key is a build-time native pin, not a value read from
 * the snapshot or supplied by JavaScript. An empty pin disables trust.
 *
 * This class intentionally does not persist sequence state. Until the native
 * monotonic store is composed, callers must not use this as a complete
 * rollback/equivocation-resistant author policy.
 */
internal class NativeAuthorRegistryVerifier(
  private val pinnedServerPublicKey: String = BuildConfig.VANGUARD_REGISTRY_SERVER_PUBLIC_KEY,
  private val campusId: String,
  private val maxSnapshotAgeMillis: Long,
  private val allowedClockSkewMillis: Long = DEFAULT_CLOCK_SKEW_MILLIS
) {
  data class VerifiedSnapshot(
    val sequence: Long,
    val issuedAtEpochMillis: Long,
    val expiresAtEpochMillis: Long,
    private val statuses: Map<String, String>
  ) {
    fun isActive(publicKey: String): Boolean = statuses[publicKey] == "active"
  }

  init {
    require(CAMPUS_ID.matches(campusId)) { "Invalid campus ID" }
    require(maxSnapshotAgeMillis > 0) { "Snapshot maximum age must be positive" }
    require(allowedClockSkewMillis >= 0) { "Clock skew must be non-negative" }
  }

  fun verify(snapshotJson: String, nowEpochMillis: Long): VerifiedSnapshot {
    require(pinnedServerPublicKey.matches(BASE64URL_59)) {
      "Native registry signing key is not configured"
    }
    require(nowEpochMillis >= 0) { "Registry clock must be non-negative" }
    val bytes = snapshotJson.toByteArray(StandardCharsets.UTF_8)
    require(bytes.size <= MAX_SNAPSHOT_BYTES) { "Author registry snapshot exceeds 8 MiB" }

    val tokener = JSONTokener(snapshotJson)
    val root = tokener.nextValue() as? JSONObject
      ?: throw IllegalArgumentException("Author registry snapshot must be an object")
    require(tokener.nextClean() == 0.toChar()) { "Unexpected trailing author registry data" }
    require(root.keySet() == ROOT_KEYS) {
      "Author registry snapshot contains missing or unexpected fields"
    }

    val version = exactLong(root, "version")
    require(version == 1L) { "Unsupported author registry version" }
    val snapshotCampus = root.get("campusId") as? String
      ?: throw IllegalArgumentException("Invalid author registry campus ID")
    require(CAMPUS_ID.matches(snapshotCampus) && snapshotCampus == campusId) {
      "Author registry snapshot belongs to a different campus"
    }
    val sequence = exactLong(root, "sequence")
    require(sequence in 1..MAX_SAFE_INTEGER) { "Invalid author registry sequence" }
    val issuedAt = exactLong(root, "issuedAtEpochMs")
    val expiresAt = exactLong(root, "expiresAtEpochMs")
    require(issuedAt in 0..MAX_SAFE_INTEGER && expiresAt in 0..MAX_SAFE_INTEGER && expiresAt > issuedAt) {
      "Invalid author registry timestamps"
    }
    require(issuedAt <= nowEpochMillis || issuedAt - nowEpochMillis <= allowedClockSkewMillis) {
      "Author registry snapshot is from the future"
    }
    require(expiresAt > nowEpochMillis && nowEpochMillis - issuedAt <= maxSnapshotAgeMillis) {
      "Author registry snapshot is expired or stale"
    }

    val signatureEncoded = root.get("signature") as? String
      ?: throw IllegalArgumentException("Invalid author registry signature")
    require(signatureEncoded.matches(BASE64URL_86)) { "Invalid author registry signature encoding" }
    val signatureBytes = decodeCanonical(signatureEncoded)
    require(signatureBytes.size == ED25519_SIGNATURE_BYTES) { "Invalid author registry signature length" }

    val authorsJson = root.get("authors") as? JSONArray
      ?: throw IllegalArgumentException("Invalid author registry entries")
    require(authorsJson.length() <= MAX_AUTHORS) { "Too many author registry entries" }
    val statuses = LinkedHashMap<String, String>(authorsJson.length())
    val canonicalAuthors = StringBuilder()
    var previous = ""
    for (index in 0 until authorsJson.length()) {
      val entry = authorsJson.get(index) as? JSONObject
        ?: throw IllegalArgumentException("Author registry entry must be an object")
      require(entry.keySet() == AUTHOR_KEYS) {
        "Author registry entry contains missing or unexpected fields"
      }
      val publicKey = entry.get("publicKey") as? String
        ?: throw IllegalArgumentException("Invalid author registry public key")
      val status = entry.get("status") as? String
        ?: throw IllegalArgumentException("Invalid author registry status")
      require(publicKey.matches(BASE64URL_59) && publicKey > previous) {
        "Author registry entries must be uniquely sorted by public key"
      }
      require(status == "active" || status == "suspended" || status == "revoked") {
        "Invalid author registry status"
      }
      previous = publicKey
      statuses[publicKey] = status
      if (index > 0) canonicalAuthors.append(',')
      canonicalAuthors.append("{\"publicKey\":\"")
        .append(publicKey)
        .append("\",\"status\":\"")
        .append(status)
        .append("\"}")
    }

    // Field order follows JavaScript UTF-16 lexicographic key ordering used by
    // Vanguard canonicalizeJson. All strings in this schema are restricted to
    // ASCII slugs/base64url/status values, avoiding serializer ambiguity.
    val canonicalUnsigned = buildString {
      append("{\"authors\":[")
      append(canonicalAuthors)
      append("],\"campusId\":\"").append(snapshotCampus)
      append("\",\"expiresAtEpochMs\":").append(expiresAt)
      append(",\"issuedAtEpochMs\":").append(issuedAt)
      append(",\"sequence\":").append(sequence)
      append(",\"version\":1}")
    }
    val message = (SIGNATURE_DOMAIN + canonicalUnsigned).toByteArray(StandardCharsets.UTF_8)
    val serverKeyBytes = decodeCanonical(pinnedServerPublicKey)
    require(serverKeyBytes.size == ED25519_SPKI_BYTES) {
      "Pinned registry signing key has an invalid length"
    }

    val verified = try {
      val provider = BouncyCastleProvider()
      val publicKey = KeyFactory.getInstance("Ed25519", provider)
        .generatePublic(X509EncodedKeySpec(serverKeyBytes))
      Signature.getInstance("Ed25519", provider).run {
        initVerify(publicKey)
        update(message)
        verify(signatureBytes)
      }
    } finally {
      message.fill(0)
      signatureBytes.fill(0)
      serverKeyBytes.fill(0)
    }
    require(verified) { "Author registry server signature verification failed" }
    return VerifiedSnapshot(sequence, issuedAt, expiresAt, statuses.toMap())
  }

  private fun exactLong(json: JSONObject, field: String): Long {
    val value = json.get(field)
    val number = value as? Number
      ?: throw IllegalArgumentException("Invalid author registry $field")
    val result = try {
      when (number) {
        is Double -> {
          require(number.isFinite() && number % 1.0 == 0.0 && number <= MAX_SAFE_INTEGER.toDouble())
          number.toLong()
        }
        is Float -> {
          require(number.isFinite() && number % 1f == 0f && number <= MAX_SAFE_INTEGER.toFloat())
          number.toLong()
        }
        else -> number.toLong().also {
          require(number.toString() == it.toString())
        }
      }
    } catch (_: Exception) {
      throw IllegalArgumentException("Invalid author registry $field")
    }
    require(result in 0..MAX_SAFE_INTEGER) { "Invalid author registry $field" }
    return result
  }

  private fun decodeCanonical(value: String): ByteArray {
    val decoded = Base64.decode(value, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    val encoded = Base64.encodeToString(decoded, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    require(encoded == value) { "Non-canonical base64url encoding" }
    return decoded
  }

  companion object {
    private const val DEFAULT_CLOCK_SKEW_MILLIS = 5 * 60 * 1000L
    private const val MAX_SNAPSHOT_BYTES = 8 * 1024 * 1024
    private const val MAX_AUTHORS = 100_000
    private const val MAX_SAFE_INTEGER = 9_007_199_254_740_991L
    private const val ED25519_SPKI_BYTES = 44
    private const val ED25519_SIGNATURE_BYTES = 64
    private const val SIGNATURE_DOMAIN = "VANGUARD_AUTHOR_REGISTRY_V1\n"
    private val CAMPUS_ID = Regex("^[a-z0-9][a-z0-9._-]{0,63}$")
    private val BASE64URL_59 = Regex("^[A-Za-z0-9_-]{59}$")
    private val BASE64URL_86 = Regex("^[A-Za-z0-9_-]{86}$")
    private val ROOT_KEYS = setOf(
      "version", "campusId", "sequence", "issuedAtEpochMs",
      "expiresAtEpochMs", "authors", "signature"
    )
    private val AUTHOR_KEYS = setOf("publicKey", "status")
  }
}
