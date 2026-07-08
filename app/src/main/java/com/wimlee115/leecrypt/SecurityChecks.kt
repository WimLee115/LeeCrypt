package com.wimlee115.leecrypt

import android.os.Build
import java.io.File

/**
 * Lichte, niet-invasieve integriteitscheck van het toestel.
 *
 * Nadrukkelijk géén `su`-proces starten (dat is omzeilbaar én triggert prompts).
 * Root-detectie is fundamenteel niet waterdicht; dit is een *indicatie*, geen garantie.
 * De app blokkeert niets — ze waarschuwt de gebruiker en laat de keuze aan hem.
 */
object SecurityChecks {

    private val ROOT_BINARIES = listOf(
        "/system/bin/su", "/system/xbin/su", "/sbin/su",
        "/system/app/Superuser.apk", "/system/bin/magisk", "/data/adb/magisk"
    )

    /** True als het toestel indicatoren van root vertoont. Geen garantie. */
    fun looksRooted(): Boolean {
        if (Build.TAGS?.contains("test-keys") == true) return true
        return ROOT_BINARIES.any { runCatching { File(it).exists() }.getOrDefault(false) }
    }
}
