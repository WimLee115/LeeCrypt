package com.wimlee115.leecrypt

import android.graphics.Bitmap
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.security.Security

/**
 * Robolectric-tests met een echte [Bitmap] (native graphics), inclusief de
 * volledige keten: versleutelen → verbergen → extraheren → ontsleutelen.
 */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34])
class StegoTest {

    companion object {
        @BeforeClass
        @JvmStatic
        fun installBouncyCastle() {
            Security.removeProvider("BC")
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }

    @Test
    fun embedExtractRoundTrip() {
        val bmp = Bitmap.createBitmap(256, 256, Bitmap.Config.ARGB_8888)
        val payload = "verborgen ✓ €".toByteArray(Charsets.UTF_8)
        assertArrayEquals(payload, StegoUtils.extract(StegoUtils.embed(bmp, payload)))
    }

    @Test(expected = IllegalArgumentException::class)
    fun capacityExceededIsRejected() {
        val bmp = Bitmap.createBitmap(8, 8, Bitmap.Config.ARGB_8888) // 64 px → 4 bytes capaciteit
        StegoUtils.embed(bmp, ByteArray(100))
    }

    @Test
    fun encryptThenHideThenDecrypt() {
        val bmp = Bitmap.createBitmap(400, 400, Bitmap.Config.ARGB_8888)
        val pw = "pw-123!".toCharArray()
        val container = CryptoUtils.encryptBytes("geheim".toByteArray(), pw, CryptoUtils.ALGO_AES_GCM)
        val stego = StegoUtils.embed(bmp, container)
        val recovered = CryptoUtils.decryptBytes(StegoUtils.extract(stego), pw)
        assertEquals("geheim", String(recovered, Charsets.UTF_8))
    }
}
