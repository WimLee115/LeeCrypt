package com.wimlee115.leecrypt

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKeys
import com.nulabinc.zxcvbn.Zxcvbn
import org.bouncycastle.crypto.generators.OpenBSDBCrypt
import org.bouncycastle.crypto.generators.SCrypt
import org.bouncycastle.crypto.params.Argon2Parameters
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.digests.Blake3Digest
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.SecretKeyFactory
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.crypto.engines.ChaCha7539Engine
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer

object CryptoUtils {

    private const val PBKDF2_ITERATIONS = 200000
    private const val KEY_LENGTH = 256
    private val secureRandom = SecureRandom()
    private val zxcvbn = Zxcvbn()

    fun deriveKey(password: String, salt: ByteArray): ByteArray {
        val spec = PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_LENGTH)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512")
        return factory.generateSecret(spec).encoded
    }

    fun encrypt(text: String, password: String, useChaCha: Boolean = false): String {
        val salt = ByteArray(16).apply { secureRandom.nextBytes(this) }
        val key = deriveKey(password, salt)
        val iv = ByteArray(12).apply { secureRandom.nextBytes(this) }
        return if (useChaCha) {
            val engine = ChaCha7539Engine()
            engine.init(true, ParametersWithIV(KeyParameter(key), iv))
            val input = text.toByteArray()
            val output = ByteArray(input.size)
            engine.processBytes(input, 0, input.size, output, 0)
            Base64.getEncoder().encodeToString(salt + iv + output)
        } else {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val secretKey = SecretKeySpec(key, "AES")
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
            val encrypted = cipher.doFinal(text.toByteArray())
            Base64.getEncoder().encodeToString(salt + iv + encrypted)
        }
    }

    fun decrypt(encrypted: String, password: String, useChaCha: Boolean = false): String {
        val decoded = Base64.getDecoder().decode(encrypted)
        val salt = decoded.copyOfRange(0, 16)
        val iv = decoded.copyOfRange(16, 28)
        val ciphertext = decoded.copyOfRange(28, decoded.size)
        val key = deriveKey(password, salt)
        return if (useChaCha) {
            val engine = ChaCha7539Engine()
            engine.init(false, ParametersWithIV(KeyParameter(key), iv))
            val output = ByteArray(ciphertext.size)
            engine.processBytes(ciphertext, 0, ciphertext.size, output, 0)
            String(output)
        } else {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val secretKey = SecretKeySpec(key, "AES")
            cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
            String(cipher.doFinal(ciphertext))
        }
    }

    fun encryptFile(context: Context, file: File, password: String): File {
        val salt = ByteArray(16).apply { secureRandom.nextBytes(this) }
        val key = deriveKey(password, salt)
        val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)
        val encryptedFile = EncryptedFile.Builder(
            File(file.parent, "${file.name}.encrypted"),
            context,
            masterKeyAlias,
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
        ).build()
        encryptedFile.openFileOutput().use { it.write(salt + file.readBytes()) }
        return File(file.parent, "${file.name}.encrypted")
    }

    fun decryptFile(context: Context, file: File, password: String): String {
        val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)
        val encryptedFile = EncryptedFile.Builder(
            file,
            context,
            masterKeyAlias,
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
        ).build()
        val content = encryptedFile.openFileInput().use { it.readBytes() }
        val salt = content.copyOfRange(0, 16)
        val data = content.copyOfRange(16, content.size)
        val key = deriveKey(password, salt)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val iv = ByteArray(12).apply { secureRandom.nextBytes(this) }
        val secretKey = SecretKeySpec(key, "AES")
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
        return String(cipher.doFinal(data))
    }

    fun hideInImage(text: String, imagePath: String): Bitmap {
        val bitmap = BitmapFactory.decodeFile(imagePath).copy(Bitmap.Config.ARGB_8888, true)
        val bytes = text.toByteArray()
        val pixels = IntArray(bitmap.width * bitmap.height)
        bitmap.getPixels(pixels, 0, bitmap.width, 0, 0, bitmap.width, bitmap.height)
        for (i in bytes.indices) {
            if (i < pixels.size) {
                pixels[i] = pixels[i] and 0xFFFFFFFE.toInt() or (bytes[i].toInt() and 1)
            }
        }
        bitmap.setPixels(pixels, 0, bitmap.width, 0, 0, bitmap.width, bitmap.height)
        return bitmap
    }

    fun extractFromImage(bitmap: Bitmap): String {
        val pixels = IntArray(bitmap.width * bitmap.height)
        bitmap.getPixels(pixels, 0, bitmap.width, 0, 0, bitmap.width, bitmap.height)
        val bytes = ByteArray(pixels.size / 8)
        for (i in bytes.indices) {
            for (j in 0..7) {
                bytes[i] = (bytes[i].toInt() shl 1 or (pixels[i * 8 + j] and 1)).toByte()
            }
        }
        return String(bytes).trimEnd('\u0000')
    }

    fun hash(text: String, algorithm: String): String {
        val digest = MessageDigest.getInstance(algorithm)
        return Base64.getEncoder().encodeToString(digest.digest(text.toByteArray()))
    }

    fun hmacSha512(text: String, key: String): String {
        val mac = Mac.getInstance("HmacSHA512")
        val secretKey = SecretKeySpec(key.toByteArray(), "HmacSHA512")
        mac.init(secretKey)
        return Base64.getEncoder().encodeToString(mac.doFinal(text.toByteArray()))
    }

    fun blake3Hash(text: String): String {
        val digest = Blake3Digest()
        val input = text.toByteArray()
        digest.update(input, 0, input.size)
        val output = ByteArray(32)
        digest.doFinal(output, 0)
        return Base64.getEncoder().encodeToString(output)
    }

    fun bcryptHash(password: String): String {
        val salt = ByteArray(16).apply { secureRandom.nextBytes(this) }
        return OpenBSDBCrypt.generate(password.toCharArray(), salt, 14)
    }

    fun scryptHash(password: String): String {
        val salt = ByteArray(16).apply { secureRandom.nextBytes(this) }
        return Base64.getEncoder().encodeToString(SCrypt.generate(password.toByteArray(), salt, 32768, 8, 1, 32))
    }

    fun argon2Hash(password: String): String {
        val generator = Argon2BytesGenerator()
        val salt = ByteArray(16).apply { secureRandom.nextBytes(this) }
        val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withSalt(salt)
            .withParallelism(4)
            .withMemoryAsKB(131072)
            .withIterations(3)
            .build()
        generator.init(params)
        val result = ByteArray(32)
        generator.generateBytes(password.toByteArray(), result)
        return Base64.getEncoder().encodeToString(result)
    }

    fun checkKeyStrength(password: String): Double {
        return zxcvbn.measure(password).score.toDouble()
    }

    fun isDeviceSecure(context: Context): Boolean {
        return try {
            val process = Runtime.getRuntime().exec("su")
            process.destroy()
            false
        } catch (e: Exception) {
            true
        }
    }
}
