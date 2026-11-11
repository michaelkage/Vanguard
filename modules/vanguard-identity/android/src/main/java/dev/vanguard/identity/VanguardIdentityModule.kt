package dev.vanguard.identity

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.system.Os
import android.util.Base64
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class VanguardIdentityModule : Module() {
  override fun definition() = ModuleDefinition {
    Name("VanguardIdentity")

    AsyncFunction("getOrCreateIdentity") {
      val context = requireNotNull(appContext.reactContext) {
        "Vanguard identity requires an active Android application context"
      }.applicationContext
      IdentityKeyStore(context).getOrCreateIdentity()
    }

    AsyncFunction("sign") { message: String ->
      val context = requireNotNull(appContext.reactContext) {
        "Vanguard identity requires an active Android application context"
      }.applicationContext
      IdentityKeyStore(context).sign(message)
    }

    AsyncFunction("verify") { publicKey: String, message: String, signature: String ->
      IdentityKeyStore.verify(publicKey, message, signature)
    }

    AsyncFunction("deleteIdentity") {
      val context = requireNotNull(appContext.reactContext) {
        "Vanguard identity requires an active Android application context"
      }.applicationContext
      IdentityKeyStore(context).deleteIdentity()
    }
  }
}

private class IdentityKeyStore(context: Context) {
  private val identityFile = File(context.noBackupFilesDir, IDENTITY_FILE_NAME)
  private val provider = BouncyCastleProvider()

  fun getOrCreateIdentity(): Map<String, String> = synchronized(LOCK) {
    if (identityFile.exists()) {
      val record = readRecord()
      validateKeyPair(record)
      return@synchronized mapOf(
        "algorithm" to ALGORITHM,
        "publicKey" to encodeUrl(record.publicKey),
        "keyProtection" to "android-keystore-wrapped"
      )
    }

    val key = getOrCreateWrappingKey()
    val pair = KeyPairGenerator.getInstance(ALGORITHM, provider).generateKeyPair()
    val privateBytes = pair.private.encoded
      ?: throw IllegalStateException("Ed25519 provider did not encode the private key")
    val publicBytes = pair.public.encoded
      ?: throw IllegalStateException("Ed25519 provider did not encode the public key")

    try {
      val encrypted = encryptPrivateKey(key, privateBytes, publicBytes)
      writeRecord(IdentityRecord(publicBytes, encrypted.first, encrypted.second))
    } finally {
      privateBytes.fill(0)
    }

    mapOf(
      "algorithm" to ALGORITHM,
      "publicKey" to encodeUrl(publicBytes),
      "keyProtection" to "android-keystore-wrapped"
    )
  }

  fun sign(message: String): String = synchronized(LOCK) {
    val messageBytes = message.toByteArray(StandardCharsets.UTF_8)
    require(messageBytes.size <= MAX_SIGNING_MESSAGE_BYTES) {
      "Signing input exceeds the protocol signing limit"
    }

    val record = readRecord()
    val privateBytes = decryptPrivateKey(getExistingWrappingKey(), record)
    try {
      val privateKey = KeyFactory.getInstance(ALGORITHM, provider)
        .generatePrivate(PKCS8EncodedKeySpec(privateBytes))
      val signer = Signature.getInstance(ALGORITHM, provider)
      signer.initSign(privateKey)
      signer.update(messageBytes)
      encodeUrl(signer.sign())
    } finally {
      privateBytes.fill(0)
    }
  }

  fun deleteIdentity(): Boolean = synchronized(LOCK) {
    val keyStore = loadAndroidKeyStore()
    val hadIdentity = identityFile.exists() || keyStore.containsAlias(WRAPPING_KEY_ALIAS)
    if (identityFile.exists() && !identityFile.delete()) {
      throw IllegalStateException("Unable to delete the local identity record")
    }
    if (keyStore.containsAlias(WRAPPING_KEY_ALIAS)) {
      keyStore.deleteEntry(WRAPPING_KEY_ALIAS)
    }
    hadIdentity
  }

  private fun validateKeyPair(record: IdentityRecord) {
    val privateBytes = decryptPrivateKey(getExistingWrappingKey(), record)
    try {
      val privateKey = KeyFactory.getInstance(ALGORITHM, provider)
        .generatePrivate(PKCS8EncodedKeySpec(privateBytes))
      val publicKey = KeyFactory.getInstance(ALGORITHM, provider)
        .generatePublic(X509EncodedKeySpec(record.publicKey))
      val challenge = KEY_VALIDATION_CHALLENGE
      val signature = Signature.getInstance(ALGORITHM, provider).run {
        initSign(privateKey)
        update(challenge)
        sign()
      }
      val valid = Signature.getInstance(ALGORITHM, provider).run {
        initVerify(publicKey)
        update(challenge)
        verify(signature)
      }
      check(valid) { "Stored Vanguard identity key pair does not match" }
    } finally {
      privateBytes.fill(0)
    }
  }

  private fun readRecord(): IdentityRecord {
    if (!identityFile.isFile) {
      throw IllegalStateException("No Vanguard identity exists on this device")
    }
    val bytes = FileInputStream(identityFile).use { input ->
      require(identityFile.length() in MIN_RECORD_BYTES.toLong()..MAX_RECORD_BYTES.toLong()) {
        "Vanguard identity record has an invalid size"
      }
      input.readBytes()
    }
    val buffer = ByteBuffer.wrap(bytes)
    val magic = ByteArray(MAGIC.size)
    buffer.get(magic)
    check(magic.contentEquals(MAGIC)) { "Unrecognized Vanguard identity record" }

    fun readField(maxBytes: Int): ByteArray {
      check(buffer.remaining() >= Int.SIZE_BYTES) { "Truncated Vanguard identity record" }
      val length = buffer.int
      check(length in 1..maxBytes && buffer.remaining() >= length) {
        "Invalid Vanguard identity record field"
      }
      return ByteArray(length).also(buffer::get)
    }

    val publicKey = readField(MAX_PUBLIC_KEY_BYTES)
    check(publicKey.size == X509_ED25519_PUBLIC_KEY_BYTES) {
      "Stored Vanguard public key has an invalid length"
    }
    val iv = readField(GCM_IV_BYTES)
    check(iv.size == GCM_IV_BYTES) { "Invalid identity encryption IV" }
    val ciphertext = readField(MAX_CIPHERTEXT_BYTES)
    check(ciphertext.size >= GCM_TAG_BYTES) { "Invalid identity ciphertext" }
    check(!buffer.hasRemaining()) { "Unexpected trailing identity record data" }
    return IdentityRecord(publicKey, iv, ciphertext)
  }

  private fun writeRecord(record: IdentityRecord) {
    val bytes = ByteArrayOutputStream().use { output ->
      DataOutputStream(output).use { data ->
        data.write(MAGIC)
        data.writeInt(record.publicKey.size)
        data.write(record.publicKey)
        data.writeInt(record.iv.size)
        data.write(record.iv)
        data.writeInt(record.ciphertext.size)
        data.write(record.ciphertext)
      }
      output.toByteArray()
    }

    val temporary = File(identityFile.parentFile, "$IDENTITY_FILE_NAME.tmp")
    FileOutputStream(temporary).use { output ->
      output.write(bytes)
      output.fd.sync()
    }
    Os.rename(temporary.absolutePath, identityFile.absolutePath)
  }

  private fun encryptPrivateKey(
    key: SecretKey,
    privateBytes: ByteArray,
    publicBytes: ByteArray
  ): Pair<ByteArray, ByteArray> {
    val cipher = Cipher.getInstance(TRANSFORMATION)
    cipher.init(Cipher.ENCRYPT_MODE, key)
    cipher.updateAAD(publicBytes)
    return cipher.iv to cipher.doFinal(privateBytes)
  }

  private fun decryptPrivateKey(key: SecretKey, record: IdentityRecord): ByteArray {
    val cipher = Cipher.getInstance(TRANSFORMATION)
    cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, record.iv))
    cipher.updateAAD(record.publicKey)
    return cipher.doFinal(record.ciphertext)
  }

  private fun getOrCreateWrappingKey(): SecretKey {
    val keyStore = loadAndroidKeyStore()
    if (keyStore.containsAlias(WRAPPING_KEY_ALIAS)) {
      return keyStore.getKey(WRAPPING_KEY_ALIAS, null) as? SecretKey
        ?: throw IllegalStateException("Vanguard wrapping key has an unexpected type")
    }

    val generator = KeyGenerator.getInstance(
      KeyProperties.KEY_ALGORITHM_AES,
      ANDROID_KEYSTORE_PROVIDER
    )
    generator.init(
      KeyGenParameterSpec.Builder(
        WRAPPING_KEY_ALIAS,
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
      )
        .setKeySize(256)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setRandomizedEncryptionRequired(true)
        .build()
    )
    return generator.generateKey()
  }

  private fun getExistingWrappingKey(): SecretKey {
    val keyStore = loadAndroidKeyStore()
    check(keyStore.containsAlias(WRAPPING_KEY_ALIAS)) {
      "Vanguard's device wrapping key is missing; identity recovery or re-enrollment is required"
    }
    return keyStore.getKey(WRAPPING_KEY_ALIAS, null) as? SecretKey
      ?: throw IllegalStateException("Vanguard wrapping key has an unexpected type")
  }

  private fun loadAndroidKeyStore(): KeyStore =
    KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER).apply { load(null) }

  companion object {
    private val LOCK = Any()
    private const val ALGORITHM = "Ed25519"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val ANDROID_KEYSTORE_PROVIDER = "AndroidKeyStore"
    private const val WRAPPING_KEY_ALIAS = "dev.vanguard.identity.wrap.v1"
    private const val IDENTITY_FILE_NAME = "vanguard-identity-v1.bin"
    private const val GCM_TAG_BITS = 128
    private const val GCM_TAG_BYTES = GCM_TAG_BITS / 8
    private const val GCM_IV_BYTES = 12
    private const val X509_ED25519_PUBLIC_KEY_BYTES = 44
    private const val MAX_SIGNING_MESSAGE_BYTES = 64 * 1024
    private const val MAX_PUBLIC_KEY_BYTES = 128
    private const val MAX_CIPHERTEXT_BYTES = 4096
    private const val MIN_RECORD_BYTES = 4 + 4 + X509_ED25519_PUBLIC_KEY_BYTES + 4 + GCM_IV_BYTES + 4 + GCM_TAG_BYTES
    private const val MAX_RECORD_BYTES = 8192
    private val MAGIC = byteArrayOf(0x56, 0x47, 0x49, 0x31)
    private val KEY_VALIDATION_CHALLENGE =
      "vanguard-ed25519-key-check-v1".toByteArray(StandardCharsets.UTF_8)

    fun verify(publicKeyEncoded: String, message: String, signatureEncoded: String): Boolean =
      try {
        val publicKeyBytes = decodeUrl(publicKeyEncoded)
        val signatureBytes = decodeUrl(signatureEncoded)
        if (
          publicKeyBytes.size != X509_ED25519_PUBLIC_KEY_BYTES ||
          signatureBytes.size != 64
        ) {
          return false
        }
        val messageBytes = message.toByteArray(StandardCharsets.UTF_8)
        if (messageBytes.size > MAX_SIGNING_MESSAGE_BYTES) return false

        val provider = BouncyCastleProvider()
        val publicKey = KeyFactory.getInstance(ALGORITHM, provider)
          .generatePublic(X509EncodedKeySpec(publicKeyBytes))
        Signature.getInstance(ALGORITHM, provider).run {
          initVerify(publicKey)
          update(messageBytes)
          verify(signatureBytes)
        }
      } catch (_: Exception) {
        false
      }

    private fun encodeUrl(bytes: ByteArray): String =
      Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

    private fun decodeUrl(value: String): ByteArray {
      require(value.isNotEmpty() && value.matches(Regex("^[A-Za-z0-9_-]+$"))) {
        "Invalid base64url encoding"
      }
      val decoded = Base64.decode(value, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
      require(encodeUrl(decoded) == value) { "Non-canonical base64url encoding" }
      return decoded
    }
  }
}

private data class IdentityRecord(
  val publicKey: ByteArray,
  val iv: ByteArray,
  val ciphertext: ByteArray
)
