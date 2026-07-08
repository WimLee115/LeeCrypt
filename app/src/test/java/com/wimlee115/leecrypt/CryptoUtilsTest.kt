package com.wimlee115.leecrypt

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.BeforeClass
import org.junit.Test
import java.security.Security

/**
 * JVM unit-tests voor de crypto-kern (geen Android-APIs nodig).
 * Dekt round-trip, authenticatie/tamper-detectie, verkeerd wachtwoord,
 * legacy-hash-weigering en nonce-uniekheid — voor beide algoritmes.
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
    fun ciphertextTamperIsRejected() {
        for (algo in algos) {
            val c = CryptoUtils.encryptBytes("data".toByteArray(), pw, algo)
            c[c.size - 1] = (c[c.size - 1].toInt() xor 1).toByte()
            assertThrows(Exception::class.java) { CryptoUtils.decryptBytes(c, pw) }
        }
    }

    @Test
    fun headerTamperIsRejected() {
        // wijzig een salt-byte in de geauthenticeerde header
        val c = CryptoUtils.encryptBytes("data".toByteArray(), pw, CryptoUtils.ALGO_AES_GCM)
        c[10] = (c[10].toInt() xor 1).toByte()
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
    fun nonceIsUniquePerEncryption() {
        val a = CryptoUtils.encrypt("x", pw)
        val b = CryptoUtils.encrypt("x", pw)
        assertNotEquals(a, b)
    }

    @Test
    fun legacyHashIsRejectedByDefault() {
        assertThrows(IllegalArgumentException::class.java) { CryptoUtils.hash("x", "MD5") }
        assertThrows(IllegalArgumentException::class.java) { CryptoUtils.hash("x", "SHA-1") }
        // SHA-256 => 32 bytes => 44 tekens base64
        assertEquals(44, CryptoUtils.hash("x", "SHA-256").length)
    }
}
