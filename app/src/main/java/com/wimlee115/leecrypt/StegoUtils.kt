package com.wimlee115.leecrypt

import android.graphics.Bitmap

/**
 * LSB-steganografie in het blauwe kanaal, met een 32-bit lengte-header.
 *
 * Belangrijk: verberg alleen *versleutelde* payloads (een LeeCrypt-container).
 * Steganografie is verhulling, geen vertrouwelijkheid — de encryptie levert die.
 *
 * Formaat in de bits: [uint32 length big-endian][length bytes payload], 1 bit per pixel.
 */
object StegoUtils {

    /** Maximaal aantal payload-bytes dat in deze afbeelding past. */
    fun capacityBytes(image: Bitmap): Int = (image.width * image.height - 32) / 8

    /** Verbergt [payload] in een kopie van [source]. Gooit als de afbeelding te klein is. */
    fun embed(source: Bitmap, payload: ByteArray): Bitmap {
        val out = source.copy(Bitmap.Config.ARGB_8888, true)
        val w = out.width
        val h = out.height
        val totalBits = 32 + payload.size * 8
        require(totalBits <= w * h) {
            "Afbeelding te klein: max ${capacityBytes(out)} bytes, payload is ${payload.size}"
        }
        val pixels = IntArray(w * h)
        out.getPixels(pixels, 0, w, 0, 0, w, h)

        var idx = 0
        fun writeBit(bit: Int) {
            pixels[idx] = (pixels[idx] and 0xFFFFFFFE.toInt()) or (bit and 1)
            idx++
        }
        // 32-bit lengte, dan de payload — MSB-first
        for (i in 31 downTo 0) writeBit((payload.size ushr i) and 1)
        for (b in payload) for (i in 7 downTo 0) writeBit((b.toInt() ushr i) and 1)

        out.setPixels(pixels, 0, w, 0, 0, w, h)
        return out
    }

    /** Haalt een eerder verborgen payload terug. Gooit als er geen geldige header is. */
    fun extract(bitmap: Bitmap): ByteArray {
        val w = bitmap.width
        val h = bitmap.height
        val pixels = IntArray(w * h)
        bitmap.getPixels(pixels, 0, w, 0, 0, w, h)

        var idx = 0
        fun readBit(): Int = pixels[idx++] and 1

        var len = 0
        for (i in 0 until 32) len = (len shl 1) or readBit()
        require(len in 0..capacityBytes(bitmap)) { "Geen geldige verborgen payload gevonden" }

        val out = ByteArray(len)
        for (j in 0 until len) {
            var b = 0
            for (i in 0 until 8) b = (b shl 1) or readBit()
            out[j] = b.toByte()
        }
        return out
    }
}
