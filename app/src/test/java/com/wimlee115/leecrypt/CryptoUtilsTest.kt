package com.wimlee115.leecrypt

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import java.io.File
import java.security.Security

/**
 * JVM unit-tests voor de crypto-kern (geen Android-APIs).
 * Round-trip, authenticatie/tamper, verkeerd wachtwoord, container-validatie,
 * bestand-crypto en hashing — voor beide algoritmes.
 */
class CryptoUtilsTest {

    companion object {
        @BeforeClass
        @JvmStatic
        fun installBouncyCastle() {
            Security.removeProvider("BC")
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }

    private val pw = "Correct-Horse-Battery-Staple-9!".toCharArray()
    private val algos = byteArrayOf(CryptoUtils.ALGO_AES_GCM, CryptoUtils.ALGO_CHACHA20_POLY1305)

    @Test
    fun roundTripBothAlgorithms() {
        val msg = "Geheime boodschap — €42, ünïcode ✓"
        for (algo in algos) {
            val container = CryptoUtils.encrypt(msg, pw, algo)
            assertEquals("algo=$algo", msg, CryptoUtils.decrypt(container, pw))
        }
    }

    @Test
    fun emptyAndLargeInput() {
        for (algo in algos) {
            assertEquals("", CryptoUtils.decrypt(CryptoUtils.encrypt("", pw, algo), pw))
            val big = "A".repeat(200_000)
            assertEquals(big, CryptoUtils.decrypt(CryptoUtils.encrypt(big, pw, algo), pw))
        }
    }

    @Test
    fun ciphertextTamperIsRejected() {
        for (algo in algos) {
            val c = CryptoUtils.encryptBytes("data".toByteArray(), pw, algo)
            c[c.size - 1] = (c[c.size - 1].toInt() xor 1).toByte()
            assertThrows(Exception::class.java) { CryptoUtils.decryptBytes(c, pw) }
        }
    }

    @Test
    fun headerTamperIsRejected() {
        val c = CryptoUtils.encryptBytes("data".toByteArray(), pw, CryptoUtils.ALGO_AES_GCM)
        c[10] = (c[10].toInt() xor 1).toByte() // salt-byte in de geauthenticeerde header
        assertThrows(Exception::class.java) { CryptoUtils.decryptBytes(c, pw) }
    }

    @Test
    fun wrongPasswordIsRejected() {
        for (algo in algos) {
            val container = CryptoUtils.encrypt("geheim", pw, algo)
            assertThrows(Exception::class.java) { CryptoUtils.decrypt(container, "fout".toCharArray()) }
        }
    }

    @Test
    fun invalidContainerIsRejected() {
        assertThrows(Exception::class.java) { CryptoUtils.decryptBytes(ByteArray(10), pw) }              // te kort
        assertThrows(Exception::class.java) { CryptoUtils.decryptBytes(ByteArray(100) { 1 }, pw) }       // fout magic
    }

    @Test
    fun fileRoundTrip() {
        for (algo in algos) {
            val input = File.createTempFile("lc-", ".txt").apply { writeText("bestandsinhoud ✓ €") }
            val enc = CryptoUtils.encryptFile(input, pw, algo)
            assertTrue(enc.name.endsWith(".enc"))
            assertNotEquals("versleuteld ≠ plaintext", input.readText(), enc.readText(Charsets.ISO_8859_1))
            val dec = CryptoUtils.decryptFile(enc, pw)
            assertEquals("bestandsinhoud ✓ €", dec.readText())
            listOf(input, enc, dec).forEach { it.delete() }
        }
    }

    @Test
    fun nonceIsUniquePerEncryption() {
        val a = CryptoUtils.encrypt("x", pw)
        val b = CryptoUtils.encrypt("x", pw)
        assertNotEquals(a, b)
    }

    @Test
    fun hashesProduceOutput() {
        assertEquals(44, CryptoUtils.hash("x", "SHA-256").length) // 32 bytes base64
        assertEquals(88, CryptoUtils.hash("x", "SHA-512").length) // 64 bytes base64
        assertTrue(CryptoUtils.blake3Hash("x").isNotEmpty())
        assertTrue(CryptoUtils.hmacSha512("x", "key".toByteArray()).isNotEmpty())
        assertTrue(CryptoUtils.argon2Hash("x".toCharArray()).isNotEmpty())
        assertTrue(CryptoUtils.scryptHash("x".toCharArray()).isNotEmpty())
        assertTrue(CryptoUtils.bcryptHash("x".toCharArray()).startsWith("\$2"))
    }

    @Test
    fun legacyHashIsRejectedByDefault() {
        assertThrows(IllegalArgumentException::class.java) { CryptoUtils.hash("x", "MD5") }
        assertThrows(IllegalArgumentException::class.java) { CryptoUtils.hash("x", "SHA-1") }
        assertTrue(CryptoUtils.hash("x", "MD5", allowLegacy = true).isNotEmpty()) // expliciet toegestaan
    }
}
