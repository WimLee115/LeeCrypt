package com.wimlee115.leecrypt

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.BeforeClass
import org.junit.Test
import java.security.Security

/**
 * Pure JVM-tests voor de stego-bitlogica (losgetrokken van Bitmap), inclusief de
 * volledige keten: versleutelen → verbergen → extraheren → ontsleutelen.
 * De pixels worden gesimuleerd als een IntArray met ruis in de laagste bits.
 */
class StegoTest {

    companion object {
        @BeforeClass
        @JvmStatic
        fun installBouncyCastle() {
            Security.removeProvider("BC")
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }

    /** Deterministische "ruis"-pixels (niet enkel nullen), zoals een echte foto. */
    private fun noisyPixels(count: Int): IntArray {
        var seed = 0x9E3779B9.toInt()
        return IntArray(count) { seed = seed * 1103515245 + 12345; seed }
    }

    @Test
    fun embedExtractRoundTrip() {
        val pixels = noisyPixels(5000)
        val payload = "verborgen ✓ €".toByteArray(Charsets.UTF_8)
        StegoUtils.embedBits(pixels, payload)
        assertArrayEquals(payload, StegoUtils.extractBits(pixels))
    }

    @Test(expected = IllegalArgumentException::class)
    fun capacityExceededIsRejected() {
        StegoUtils.embedBits(noisyPixels(64), ByteArray(100)) // 64 px → 4 bytes capaciteit
    }

    @Test
    fun encryptThenHideThenDecrypt() {
        val pixels = noisyPixels(6000)
        val pw = "pw-123!".toCharArray()
        val container = CryptoUtils.encryptBytes("geheim".toByteArray(), pw, CryptoUtils.ALGO_AES_GCM)
        StegoUtils.embedBits(pixels, container)
        val recovered = CryptoUtils.decryptBytes(StegoUtils.extractBits(pixels), pw)
        assertEquals("geheim", String(recovered, Charsets.UTF_8))
    }
}
