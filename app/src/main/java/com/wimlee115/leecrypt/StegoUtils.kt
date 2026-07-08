package com.wimlee115.leecrypt

import android.graphics.Bitmap

/**
 * LSB-steganografie in het blauwe kanaal, met een 32-bit lengte-header.
 *
 * Belangrijk: verberg alleen *versleutelde* payloads (een LeeCrypt-container).
 * Steganografie is verhulling, geen vertrouwelijkheid — de encryptie levert die.
 *
 * De bit-logica ([embedBits]/[extractBits]) is bewust losgetrokken van [Bitmap],
 * zodat ze puur op de JVM te testen is (1 bit per pixel, MSB-first,
 * [uint32 length][length bytes payload]).
 */
object StegoUtils {

    fun capacityBytes(image: Bitmap): Int = capacityBytes(image.width * image.height)

    internal fun capacityBytes(pixelCount: Int): Int = (pixelCount - 32) / 8

    /** Verbergt [payload] in een kopie van [source]. Gooit als de afbeelding te klein is. */
    fun embed(source: Bitmap, payload: ByteArray): Bitmap {
        val out = source.copy(Bitmap.Config.ARGB_8888, true)
        val pixels = IntArray(out.width * out.height)
        out.getPixels(pixels, 0, out.width, 0, 0, out.width, out.height)
        embedBits(pixels, payload)
        out.setPixels(pixels, 0, out.width, 0, 0, out.width, out.height)
        return out
    }

    /** Haalt een eerder verborgen payload terug. Gooit als er geen geldige header is. */
    fun extract(bitmap: Bitmap): ByteArray {
        val pixels = IntArray(bitmap.width * bitmap.height)
        bitmap.getPixels(pixels, 0, bitmap.width, 0, 0, bitmap.width, bitmap.height)
        return extractBits(pixels)
    }

    /** Schrijft de lengte-header + payload in de LSB van [pixels] (in-place). */
    internal fun embedBits(pixels: IntArray, payload: ByteArray) {
        require(32 + payload.size * 8 <= pixels.size) {
            "Afbeelding te klein: max ${capacityBytes(pixels.size)} bytes, payload is ${payload.size}"
        }
        var idx = 0
        fun writeBit(bit: Int) {
            pixels[idx] = (pixels[idx] and 0xFFFFFFFE.toInt()) or (bit and 1)
            idx++
        }
        for (i in 31 downTo 0) writeBit((payload.size ushr i) and 1)
        for (b in payload) for (i in 7 downTo 0) writeBit((b.toInt() ushr i) and 1)
    }

    /** Leest de lengte-header + payload uit de LSB van [pixels]. */
    internal fun extractBits(pixels: IntArray): ByteArray {
        var idx = 0
        fun readBit(): Int = pixels[idx++] and 1
        var len = 0
        for (i in 0 until 32) len = (len shl 1) or readBit()
        require(len in 0..capacityBytes(pixels.size)) { "Geen geldige verborgen payload gevonden" }
        val out = ByteArray(len)
        for (j in 0 until len) {
            var b = 0
            for (i in 0 until 8) b = (b shl 1) or readBit()
            out[j] = b.toByte()
        }
        return out
    }
}
