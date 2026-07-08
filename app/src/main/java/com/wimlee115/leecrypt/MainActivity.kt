package com.wimlee115.leecrypt

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.nulabinc.zxcvbn.Zxcvbn
import com.wimlee115.leecrypt.ui.LeeCryptTheme
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

/**
 * LeeCrypt v2 — Jetpack Compose UI (Material 3, Matrix-thema).
 * FragmentActivity is vereist voor BiometricPrompt.
 */
class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Security.removeProvider("BC")
        Security.insertProviderAt(BouncyCastleProvider(), 1)
        setContent {
            LeeCryptTheme {
                LeeCryptApp(activity = this)
            }
        }
    }
}

private enum class Algo(val label: String, val id: Byte) {
    AES("AES-256-GCM", CryptoUtils.ALGO_AES_GCM),
    CHACHA("ChaCha20-Poly1305", CryptoUtils.ALGO_CHACHA20_POLY1305)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LeeCryptApp(activity: FragmentActivity) {
    val tabs = listOf("Text", "File", "Terminal")
    var selected by remember { mutableIntStateOf(0) }
    val rooted = remember { SecurityChecks.looksRooted() }

    Scaffold(
        topBar = { TopAppBar(title = { Text("LeeCrypt", fontFamily = FontFamily.Monospace) }) }
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {
            if (rooted) {
                Surface(color = MaterialTheme.colorScheme.errorContainer) {
                    Text(
                        "⚠ Dit toestel vertoont root-indicatoren. Root kan de beveiliging ondermijnen.",
                        Modifier.padding(12.dp),
                        color = MaterialTheme.colorScheme.onErrorContainer
                    )
                }
            }
            TabRow(selectedTabIndex = selected) {
                tabs.forEachIndexed { i, t ->
                    Tab(selected = selected == i, onClick = { selected = i },
                        text = { Text(t, fontFamily = FontFamily.Monospace) })
                }
            }
            when (selected) {
                0 -> TextScreen(activity)
                1 -> FileScreen()
                else -> TerminalScreen()
            }
        }
    }
}

@Composable
private fun TextScreen(activity: FragmentActivity) {
    val context = LocalContext.current
    val zxcvbn = remember { Zxcvbn() }
    var input by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var algo by remember { mutableStateOf(Algo.AES) }
    var output by remember { mutableStateOf("") }

    val strength = remember(password) { if (password.isEmpty()) 0 else zxcvbn.measure(password).score }

    Column(
        Modifier.fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        OutlinedTextField(input, { input = it }, Modifier.fillMaxWidth(),
            label = { Text("Tekst / container") }, minLines = 3)

        OutlinedTextField(password, { password = it }, Modifier.fillMaxWidth(),
            label = { Text("Wachtwoord") }, singleLine = true,
            visualTransformation = PasswordVisualTransformation())
        LinearProgressIndicator(
            progress = { strength / 4f },
            Modifier.fillMaxWidth(),
        )
        Text("Sterkte: $strength/4", style = MaterialTheme.typography.labelSmall)

        AlgoSelector(algo) { algo = it }

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = {
                    output = runCrypto(password, minStrength = 2) {
                        CryptoUtils.encrypt(input, password.toCharArray(), algo.id)
                    }
                },
                modifier = Modifier.weight(1f)
            ) { Text("Encrypt") }
            OutlinedButton(
                onClick = { output = runCrypto(password) { CryptoUtils.decrypt(input.trim(), password.toCharArray()) } },
                modifier = Modifier.weight(1f)
            ) { Text("Decrypt") }
        }

        HashRow(input) { output = it }

        OutlinedButton(
            onClick = {
                if (password.isBlank()) { output = "Voer eerst een wachtwoord in om op te slaan."; return@OutlinedButton }
                promptBiometric(activity, "Sleutel opslaan") {
                    runCatching { KeyVault(context).saveKey("default", password.toCharArray()) }
                        .onSuccess { output = "Sleutel versleuteld opgeslagen." }
                        .onFailure { output = "Opslaan mislukt: ${it.message}" }
                }
            },
            modifier = Modifier.fillMaxWidth()
        ) { Text("🔒 Sleutel opslaan (biometrisch)") }

        if (output.isNotEmpty()) {
            SelectionContainer {
                Card(Modifier.fillMaxWidth()) {
                    Text(output, Modifier.padding(12.dp), fontFamily = FontFamily.Monospace,
                        style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}

@Composable
private fun AlgoSelector(current: Algo, onSelect: (Algo) -> Unit) {
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
        Algo.entries.forEach { a ->
            FilterChip(selected = current == a, onClick = { onSelect(a) }, label = { Text(a.label) })
        }
    }
}

@Composable
private fun HashRow(input: String, onResult: (String) -> Unit) {
    val hashes = listOf("SHA-256", "SHA-512", "BLAKE3", "Argon2", "SCrypt", "BCrypt")
    var expanded by remember { mutableStateOf(false) }
    Box {
        OutlinedButton(onClick = { expanded = true }, Modifier.fillMaxWidth()) { Text("Hash ▾") }
        DropdownMenu(expanded, { expanded = false }) {
            hashes.forEach { h ->
                DropdownMenuItem(text = { Text(h) }, onClick = {
                    expanded = false
                    onResult(runCatching {
                        when (h) {
                            "SHA-256", "SHA-512" -> CryptoUtils.hash(input, h)
                            "BLAKE3" -> CryptoUtils.blake3Hash(input)
                            "Argon2" -> CryptoUtils.argon2Hash(input.toCharArray())
                            "SCrypt" -> CryptoUtils.scryptHash(input.toCharArray())
                            "BCrypt" -> CryptoUtils.bcryptHash(input.toCharArray())
                            else -> "?"
                        }
                    }.getOrElse { "Fout: ${it.message}" })
                })
            }
        }
    }
}

@Composable
private fun FileScreen() {
    Column(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("Bestandsversleuteling", style = MaterialTheme.typography.titleMedium)
        Text(
            "Kies een bestand via de systeem-bestandskiezer (SAF). Elk bestand wordt " +
                "versleuteld tot een zelfbeschrijvende LeeCrypt-container (.enc).",
            style = MaterialTheme.typography.bodySmall
        )
        // De volledige SAF-flow (OpenDocument/CreateDocument + ContentResolver) wordt in
        // FileCrypto gekoppeld; UI-knoppen volgen daar. Zie CryptoUtils.encryptFile/decryptFile.
        Text("(SAF-koppeling: zie CryptoUtils.encryptBytes/decryptBytes)",
            style = MaterialTheme.typography.labelSmall)
    }
}

@Composable
private fun TerminalScreen() {
    var command by remember { mutableStateOf("") }
    var log by remember { mutableStateOf("LeeCrypt terminal — typ 'help'.\n") }
    Column(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        SelectionContainer {
            Card(Modifier.fillMaxWidth().weight(1f)) {
                Text(log, Modifier.padding(12.dp).verticalScroll(rememberScrollState()),
                    fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
            }
        }
        OutlinedTextField(command, { command = it }, Modifier.fillMaxWidth(),
            label = { Text("commando") }, singleLine = true,
            trailingIcon = {
                TextButton(onClick = {
                    log += "> $command\n" + runTerminal(command) + "\n"
                    command = ""
                }) { Text("run") }
            })
    }
}

// ---------------------------------------------------------------- helpers (niet-composable)

private fun runCrypto(password: String, minStrength: Int = -1, block: () -> String): String =
    when {
        password.isBlank() -> "Voer een wachtwoord in."
        else -> runCatching(block).getOrElse { "Fout: ${it.message}" }
    }

private fun runTerminal(command: String): String {
    val parts = command.trim().split(" ", limit = 3)
    return when (parts.getOrNull(0)) {
        "help" -> "commando's: hash <sha-256|sha-512|blake3> <tekst>"
        "hash" -> if (parts.size == 3) runCatching {
            when (parts[1].uppercase()) {
                "SHA-256" -> CryptoUtils.hash(parts[2], "SHA-256")
                "SHA-512" -> CryptoUtils.hash(parts[2], "SHA-512")
                "BLAKE3" -> CryptoUtils.blake3Hash(parts[2])
                else -> "onbekend algoritme"
            }
        }.getOrElse { "fout: ${it.message}" } else "gebruik: hash <type> <tekst>"
        else -> "onbekend commando (typ 'help')"
    }
}

private fun promptBiometric(activity: FragmentActivity, title: String, onSuccess: () -> Unit) {
    val prompt = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity),
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = onSuccess()
        })
    prompt.authenticate(
        BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle("Bevestig met biometrie")
            .setNegativeButtonText("Annuleren")
            .build()
    )
}
