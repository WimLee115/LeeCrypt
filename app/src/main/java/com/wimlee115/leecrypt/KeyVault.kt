package com.wimlee115.leecrypt

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Versleutelde opslag voor door de gebruiker bewaarde sleutels/wachtwoorden.
 *
 * De onderliggende masterkey leeft in de Android Keystore (hardware-backed waar
 * beschikbaar). Toegang wordt in de UI achter een [androidx.biometric.BiometricPrompt]
 * gezet; deze klasse levert de versleutelde persistente laag daaronder.
 *
 * NB: sla hier bij voorkeur geen langlevende plaintext-wachtwoorden op; bedoeld
 * voor door de gebruiker geëxporteerde/geïmporteerde sleutels.
 */
class KeyVault(context: Context) {

    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val prefs = EncryptedSharedPreferences.create(
        context,
        PREFS_NAME,
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    fun saveKey(alias: String, secret: CharArray) {
        prefs.edit().putString(alias, String(secret)).apply()
    }

    fun loadKey(alias: String): CharArray? = prefs.getString(alias, null)?.toCharArray()

    fun deleteKey(alias: String) {
        prefs.edit().remove(alias).apply()
    }

    fun aliases(): Set<String> = prefs.all.keys

    companion object {
        private const val PREFS_NAME = "leecrypt_vault"
    }
}
