package com.wimlee115.leecrypt

import org.bouncycastle.crypto.digests.Blake3Digest
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.generators.OpenBSDBCrypt
import org.bouncycastle.crypto.generators.SCrypt
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.Argon2Parameters
import org.bouncycastle.crypto.params.KeyParameter
import java.io.File
import java.nio.CharBuffer
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Cryptografische kern van LeeCrypt (v2).
 *
 * Ontwerp-uitgangspunten:
 *  - Authenticated encryption (AEAD) altijd — AES-256-GCM of ChaCha20-Poly1305.
 *    Nooit een kale stream cipher zonder MAC.
 *  - Eén zelfbeschrijvend, geauthenticeerd container-formaat voor tekst én bestanden.
 *  - Sleutel-afleiding met Argon2id (memory-hard), niet met een snelle hash.
 *  - Sleutels worden na gebruik met nullen overschreven.
 *  - Wachtwoorden als CharArray, zodat ze wisbaar zijn (String is immutable).
 *
 * Container-formaat (bytes):
 *   "LCR2"(4) | version(1) | algo(1) | kdf(1) | salt(16) | nonce(12) | ciphertext‖tag(...)
 * De volledige header (35 bytes) wordt als AAD meegetekend, zodat algoritme-keuze,
 * salt en nonce niet ongemerkt gewijzigd kunnen worden.
 */
object CryptoUtils {

    private val MAGIC = byteArrayOf('L'.code.toByte(), 'C'.code.toByte(), 'R'.code.toByte(), '2'.code.toByte())
    private const val VERSION: Byte = 2

    /** Algoritme-ids in het container-formaat. */
    const val ALGO_AES_GCM: Byte = 1
    const val ALGO_CHACHA20_POLY1305: Byte = 2
    private const val KDF_ARGON2ID: Byte = 1

    private const val SALT_LEN = 16
    private const val NONCE_LEN = 12
    private const val TAG_BITS = 128
    private const val KEY_LEN = 32 // 256-bit
    private const val HEADER_LEN = 4 + 1 + 1 + 1 + SALT_LEN + NONCE_LEN // = 35

    // Argon2id-parameters (memory-hard, OWASP-conform).
    private const val ARGON2_ITERATIONS = 3
    private const val ARGON2_MEMORY_KB = 65536 // 64 MB
    private const val ARGON2_PARALLELISM = 4

    private val secureRandom = SecureRandom()

    // ---------------------------------------------------------------- tekst

    /** Versleutelt tekst en geeft de container terug als Base64-string. */
    fun encrypt(plaintext: String, password: CharArray, algo: Byte = ALGO_AES_GCM): String {
        val pt = plaintext.toByteArray(StandardCharsets.UTF_8)
        try {
            return Base64.getEncoder().encodeToString(encryptBytes(pt, password, algo))
        } finally {
            pt.fill(0)
        }
    }

    /** Ontsleutelt een Base64-container terug naar tekst. */
    fun decrypt(base64Container: String, password: CharArray): String {
        val pt = decryptBytes(Base64.getDecoder().decode(base64Container), password)
        try {
            return String(pt, StandardCharsets.UTF_8)
        } finally {
            pt.fill(0)
        }
    }

    // ---------------------------------------------------------------- bestand

    /** Versleutelt een bestand naar `<naam>.enc` en geeft dat bestand terug. */
    fun encryptFile(input: File, password: CharArray, algo: Byte = ALGO_AES_GCM): File {
        val data = input.readBytes()
        try {
            val out = File(input.parentFile, input.name + ".enc")
            out.writeBytes(encryptBytes(data, password, algo))
            return out
        } finally {
            data.fill(0)
        }
    }

    /** Ontsleutelt een `.enc`-bestand naar `<naam>.dec` en geeft dat bestand terug. */
    fun decryptFile(input: File, password: CharArray): File {
        val container = input.readBytes()
        val data = decryptBytes(container, password)
        try {
            val baseName = input.name.removeSuffix(".enc")
            val out = File(input.parentFile, "$baseName.dec")
            out.writeBytes(data)
            return out
        } finally {
            data.fill(0)
        }
    }

    // ---------------------------------------------------------------- kern

    /** Bouwt de volledige container (header + AEAD-output) voor willekeurige bytes. */
    fun encryptBytes(plaintext: ByteArray, password: CharArray, algo: Byte): ByteArray {
        require(algo == ALGO_AES_GCM || algo == ALGO_CHACHA20_POLY1305) { "Onbekend algoritme" }
        val salt = randomBytes(SALT_LEN)
        val nonce = randomBytes(NONCE_LEN)
        val header = buildHeader(algo, salt, nonce)
        val key = deriveKey(password, salt)
        try {
            val ct = aeadSeal(algo, key, nonce, header, plaintext)
            return header + ct
        } finally {
            key.fill(0)
        }
    }

    /** Parseert een container, verifieert en ontsleutelt. Gooit bij manipulatie/verkeerd wachtwoord. */
    fun decryptBytes(container: ByteArray, password: CharArray): ByteArray {
        require(container.size > HEADER_LEN) { "Ongeldige of te korte container" }
        require(container.copyOfRange(0, 4).contentEquals(MAGIC)) { "Geen LeeCrypt-container" }
        val version = container[4]
        require(version == VERSION) { "Niet-ondersteunde containerversie: $version" }
        val algo = container[5]
        val kdf = container[6]
        require(kdf == KDF_ARGON2ID) { "Niet-ondersteunde KDF: $kdf" }
        val salt = container.copyOfRange(7, 7 + SALT_LEN)
        val nonce = container.copyOfRange(7 + SALT_LEN, HEADER_LEN)
        val header = container.copyOfRange(0, HEADER_LEN)
        val ct = container.copyOfRange(HEADER_LEN, container.size)
        val key = deriveKey(password, salt)
        try {
            return aeadOpen(algo, key, nonce, header, ct)
        } finally {
            key.fill(0)
        }
    }

    private fun buildHeader(algo: Byte, salt: ByteArray, nonce: ByteArray): ByteArray {
        val h = ByteArray(HEADER_LEN)
        System.arraycopy(MAGIC, 0, h, 0, 4)
        h[4] = VERSION
        h[5] = algo
        h[6] = KDF_ARGON2ID
        System.arraycopy(salt, 0, h, 7, SALT_LEN)
        System.arraycopy(nonce, 0, h, 7 + SALT_LEN, NONCE_LEN)
        return h
    }

    /** AEAD-encryptie; retourneert ciphertext‖tag. */
    private fun aeadSeal(algo: Byte, key: ByteArray, nonce: ByteArray, aad: ByteArray, pt: ByteArray): ByteArray =
        when (algo) {
            ALGO_AES_GCM -> {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, nonce))
                cipher.updateAAD(aad)
                cipher.doFinal(pt)
            }
            ALGO_CHACHA20_POLY1305 -> chacha(true, key, nonce, aad, pt)
            else -> throw IllegalArgumentException("Onbekend algoritme")
        }

    /** AEAD-decryptie; verifieert de tag en retourneert de plaintext. */
    private fun aeadOpen(algo: Byte, key: ByteArray, nonce: ByteArray, aad: ByteArray, ct: ByteArray): ByteArray =
        when (algo) {
            ALGO_AES_GCM -> {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, nonce))
                cipher.updateAAD(aad)
                cipher.doFinal(ct)
            }
            ALGO_CHACHA20_POLY1305 -> chacha(false, key, nonce, aad, ct)
            else -> throw IllegalArgumentException("Onbekend algoritme")
        }

    private fun chacha(encrypt: Boolean, key: ByteArray, nonce: ByteArray, aad: ByteArray, input: ByteArray): ByteArray {
        val engine = ChaCha20Poly1305()
        engine.init(encrypt, AEADParameters(KeyParameter(key), TAG_BITS, nonce, aad))
        val out = ByteArray(engine.getOutputSize(input.size))
        var len = engine.processBytes(input, 0, input.size, out, 0)
        len += engine.doFinal(out, len) // gooit InvalidCipherTextException bij foute tag
        return if (len == out.size) out else out.copyOfRange(0, len)
    }

    // ---------------------------------------------------------------- KDF

    private fun deriveKey(password: CharArray, salt: ByteArray): ByteArray {
        val pwBytes = charsToUtf8(password)
        try {
            val gen = Argon2BytesGenerator()
            gen.init(
                Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                    .withSalt(salt)
                    .withIterations(ARGON2_ITERATIONS)
                    .withMemoryAsKB(ARGON2_MEMORY_KB)
                    .withParallelism(ARGON2_PARALLELISM)
                    .build()
            )
            val key = ByteArray(KEY_LEN)
            gen.generateBytes(pwBytes, key)
            return key
        } finally {
            pwBytes.fill(0)
        }
    }

    // ---------------------------------------------------------------- hashing

    private val SECURE_HASHES = setOf("SHA-256", "SHA-384", "SHA-512")

    /** Hash met een JCA-digest. Legacy (MD5/SHA-1) wordt geweigerd tenzij expliciet toegestaan. */
    fun hash(text: String, algorithm: String, allowLegacy: Boolean = false): String {
        if (!allowLegacy && algorithm.uppercase() !in SECURE_HASHES) {
            throw IllegalArgumentException("$algorithm is verouderd/onveilig; gebruik SHA-256 of hoger")
        }
        val digest = MessageDigest.getInstance(algorithm)
        return Base64.getEncoder().encodeToString(digest.digest(text.toByteArray(StandardCharsets.UTF_8)))
    }

    fun hmacSha512(text: String, key: ByteArray): String {
        val mac = Mac.getInstance("HmacSHA512")
        mac.init(SecretKeySpec(key, "HmacSHA512"))
        return Base64.getEncoder().encodeToString(mac.doFinal(text.toByteArray(StandardCharsets.UTF_8)))
    }

    fun blake3Hash(text: String): String {
        val digest = Blake3Digest()
        val input = text.toByteArray(StandardCharsets.UTF_8)
        digest.update(input, 0, input.size)
        val output = ByteArray(32)
        digest.doFinal(output, 0)
        return Base64.getEncoder().encodeToString(output)
    }

    // ---- wachtwoord-hashing (voor opslag/vergelijking, niet voor encryptie) ----

    fun bcryptHash(password: CharArray): String =
        OpenBSDBCrypt.generate(password, randomBytes(16), 12)

    fun scryptHash(password: CharArray): String {
        val pw = charsToUtf8(password)
        try {
            return Base64.getEncoder().encodeToString(SCrypt.generate(pw, randomBytes(16), 32768, 8, 1, 32))
        } finally {
            pw.fill(0)
        }
    }

    fun argon2Hash(password: CharArray): String =
        Base64.getEncoder().encodeToString(deriveKey(password, randomBytes(16)))

    // ---------------------------------------------------------------- helpers

    private fun randomBytes(n: Int): ByteArray = ByteArray(n).also { secureRandom.nextBytes(it) }

    private fun charsToUtf8(chars: CharArray): ByteArray {
        val bb = StandardCharsets.UTF_8.encode(CharBuffer.wrap(chars))
        val out = ByteArray(bb.remaining())
        bb.get(out)
        java.util.Arrays.fill(bb.array(), 0.toByte())
        return out
    }
}
