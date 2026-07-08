package com.wimlee115.leecrypt

import android.animation.ValueAnimator
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.nfc.NfcAdapter
import android.os.Bundle
import android.widget.*
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment
import androidx.fragment.app.FragmentActivity
import androidx.viewpager2.adapter.FragmentStateAdapter
import androidx.viewpager2.widget.ViewPager2
import com.google.android.material.tabs.TabLayout
import com.google.android.material.tabs.TabLayoutMediator
import com.google.zxing.integration.android.IntentIntegrator
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security
import android.os.Environment
import java.io.File
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import android.widget.Toast
import com.squareup.sqldelight.android.AndroidSqliteDriver
import com.squareup.sqldelight.db.SqlDriver
import com.squareup.sqldelight.runtime.coroutines.asFlow
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import java.util.UUID

class MainActivity : AppCompatActivity() {

    private lateinit var viewPager: ViewPager2
    private lateinit var outputText: TextView
    private lateinit var terminalInput: EditText
    private lateinit var biometricPrompt: BiometricPrompt
    private val requestPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) startQrScan() else toast("Camera permission denied")
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        Security.addProvider(BouncyCastleProvider())

        viewPager = findViewById(R.id.viewPager)
        val tabLayout = findViewById<TabLayout>(R.id.tabLayout)

        viewPager.adapter = ViewPagerAdapter(this)
        TabLayoutMediator(tabLayout, viewPager) { tab, position ->
            tab.text = when (position) {
                0 -> getString(R.string.tab_text)
                1 -> getString(R.string.tab_file)
                else -> getString(R.string.tab_terminal)
            }
        }.attach()

        if (!CryptoUtils.isDeviceSecure(this)) {
            toast("Warning: Device appears to be rooted. Security risks detected!")
        }

        biometricPrompt = BiometricPrompt(this, ContextCompat.getMainExecutor(this), object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                toast("Biometric authentication successful")
            }
        })

        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.addPrimaryClipChangedListener {
            val clip = clipboard.primaryClip?.getItemAt(0)?.text?.toString()
            if (clip != null && clip.isNotEmpty()) {
                toast("Clipboard detected. Encrypt it in Text tab!")
            }
        }
    }

    private fun startQrScan() {
        val integrator = IntentIntegrator(this)
        integrator.setDesiredBarcodeFormats(IntentIntegrator.QR_CODE)
        integrator.setPrompt("Scan QR for Key")
        integrator.initiateScan()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        val result = IntentIntegrator.parseActivityResult(requestCode, resultCode, data)
        if (result != null && result.contents != null) {
            val fragment = supportFragmentManager.fragments[viewPager.currentItem]
            if (fragment is TextFragment) {
                fragment.setKey(result.contents)
            }
        } else {
            super.onActivityResult(requestCode, resultCode, data)
        }
    }

    private fun toast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
    }

    class ViewPagerAdapter(fragmentActivity: FragmentActivity) : FragmentStateAdapter(fragmentActivity) {
        override fun getItemCount(): Int = 3
        override fun createFragment(position: Int): Fragment = when (position) {
            0 -> TextFragment()
            1 -> FileFragment()
            else -> TerminalFragment()
        }
    }
}

class TextFragment : Fragment(R.layout.fragment_text) {
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val inputText = view.findViewById<EditText>(R.id.inputText)
        val keyText = view.findViewById<EditText>(R.id.keyText)
        val keyStrength = view.findViewById<TextView>(R.id.keyStrength)
        val hashSpinner = view.findViewById<Spinner>(R.id.hashSpinner)
        val encryptButton = view.findViewById<Button>(R.id.encryptButton)
        val decryptButton = view.findViewById<Button>(R.id.decryptButton)
        val hashButton = view.findViewById<Button>(R.id.hashButton)
        val qrScanButton = view.findViewById<Button>(R.id.qrScanButton)
        val qrExportButton = view.findViewById<Button>(R.id.qrExportButton)
        val saveKeyButton = view.findViewById<Button>(R.id.saveKeyButton)
        val stegoButton = view.findViewById<Button>(R.id.stegoButton)
        val outputText = view.findViewById<TextView>(R.id.outputText)

        keyText.addTextChangedListener(object : android.text.TextWatcher {
            override fun afterTextChanged(s: android.text.Editable?) {
                val strength = CryptoUtils.checkKeyStrength(s.toString())
                keyStrength.text = "Key Strength: ${strength}/5"
            }
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
        })

        encryptButton.setOnClickListener {
            val key = keyText.text.toString()
            if (CryptoUtils.checkKeyStrength(key) < 3.0) {
                toast("Weak key! Use a stronger one.")
                return@setOnClickListener
            }
            try {
                val result = CryptoUtils.encrypt(inputText.text.toString(), key)
                animateOutput(outputText, result)
            } catch (e: Exception) {
                animateOutput(outputText, "Error: ${e.message}")
            }
        }

        decryptButton.setOnClickListener {
            try {
                val result = CryptoUtils.decrypt(inputText.text.toString(), keyText.text.toString())
                animateOutput(outputText, result)
            } catch (e: Exception) {
                animateOutput(outputText, "Error: ${e.message}")
            }
        }

        hashButton.setOnClickListener {
            val text = inputText.text.toString()
            val hashType = hashSpinner.selectedItem.toString()
            val key = keyText.text.toString()
            val hashed = when (hashType) {
                "MD5" -> CryptoUtils.hash(text, "MD5")
                "SHA-1" -> CryptoUtils.hash(text, "SHA-1")
                "SHA-256" -> CryptoUtils.hash(text, "SHA-256")
                "SHA-512" -> CryptoUtils.hash(text, "SHA-512")
                "HMAC-SHA512" -> CryptoUtils.hmacSha512(text, key)
                "BCrypt" -> CryptoUtils.bcryptHash(text)
                "SCrypt" -> CryptoUtils.scryptHash(text)
                "Argon2" -> CryptoUtils.argon2Hash(text)
                "BLAKE3" -> CryptoUtils.blake3Hash(text)
                else -> "Unsupported"
            }
            animateOutput(outputText, hashed)
        }

        qrScanButton.setOnClickListener {
            (activity as MainActivity).requestPermission.launch(android.Manifest.permission.CAMERA)
        }

        qrExportButton.setOnClickListener {
            val text = outputText.text.toString()
            if (text.isNotEmpty()) {
                val integrator = IntentIntegrator(activity)
                integrator.shareText(text)
            } else {
                toast("No output to export")
            }
        }

        saveKeyButton.setOnClickListener {
            val key = keyText.text.toString()
            if (key.isNotEmpty()) {
                val promptInfo = BiometricPrompt.PromptInfo.Builder()
                    .setTitle("Authenticate to Save Key")
                    .setSubtitle("Use fingerprint to save key securely")
                    .setNegativeButtonText("Cancel")
                    .build()
                (activity as MainActivity).biometricPrompt.authenticate(promptInfo)
            } else {
                toast("Enter a key to save")
            }
        }

        stegoButton.setOnClickListener {
            val intent = Intent(Intent.ACTION_GET_CONTENT)
            intent.type = "image/png"
            startActivityForResult(intent, 1)
        }

        outputText.setOnLongClickListener {
            val clipboard = requireContext().getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            clipboard.setPrimaryClip(ClipData.newPlainText("LeeCrypt Output", outputText.text))
            toast("Output copied")
            true
        }
    }

    fun setKey(key: String) {
        view?.findViewById<EditText>(R.id.keyText)?.setText(key)
    }

    private fun animateOutput(textView: TextView, text: String) {
        textView.text = ""
        val animator = ValueAnimator.ofInt(0, text.length)
        animator.duration = 1500L
        animator.addUpdateListener { animation ->
            val charCount = animation.animatedValue as Int
            textView.text = text.substring(0, charCount)
        }
        animator.start()
    }

    private fun toast(message: String) {
        Toast.makeText(requireContext(), message, Toast.LENGTH_LONG).show()
    }
}

class FileFragment : Fragment(R.layout.fragment_file) {
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val filePath = view.findViewById<EditText>(R.id.filePath)
        val keyText = view.findViewById<EditText>(R.id.keyText)
        val progressBar = view.findViewById<ProgressBar>(R.id.progressBar)
        val encryptButton = view.findViewById<Button>(R.id.encryptFileButton)
        val decryptButton = view.findViewById<Button>(R.id.decryptFileButton)

        encryptButton.setOnClickListener {
            val file = File(filePath.text.toString())
            if (file.exists() && file.length() <= 10 * 1024 * 1024) {
                progressBar.visibility = View.VISIBLE
                try {
                    val result = CryptoUtils.encryptFile(requireContext(), file, keyText.text.toString())
                    toast("File encrypted: ${result.absolutePath}")
                } catch (e: Exception) {
                    toast("Error: ${e.message}")
                } finally {
                    progressBar.visibility = View.GONE
                }
            } else {
                toast("File too large or not found")
            }
        }

        decryptButton.setOnClickListener {
            val file = File(filePath.text.toString())
            if (file.exists()) {
                progressBar.visibility = View.VISIBLE
                try {
                    val result = CryptoUtils.decryptFile(requireContext(), file, keyText.text.toString())
                    toast("Decrypted: $result")
                } catch (e: Exception) {
                    toast("Error: ${e.message}")
                } finally {
                    progressBar.visibility = View.GONE
                }
            } else {
                toast("File not found")
            }
        }
    }

    private fun toast(message: String) {
        Toast.makeText(requireContext(), message, Toast.LENGTH_LONG).show()
    }
}

class TerminalFragment : Fragment(R.layout.fragment_terminal) {
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val terminalInput = view.findViewById<EditText>(R.id.terminalInput)
        val outputText = view.findViewById<TextView>(R.id.outputText)

        terminalInput.setOnEditorActionListener { _, _, _ ->
            val command = terminalInput.text.toString()
            when {
                command.startsWith("encrypt -f ") -> {
                    val text = command.removePrefix("encrypt -f ")
                    try {
                        val result = CryptoUtils.encrypt(text, "default_key") // Gebruik saved key indien nodig
                        animateOutput(outputText, result)
                    } catch (e: Exception) {
                        animateOutput(outputText, "Error: ${e.message}")
                    }
                }
                command.startsWith("decrypt -f ") -> {
                    val text = command.removePrefix("decrypt -f ")
                    try {
                        val result = CryptoUtils.decrypt(text, "default_key")
                        animateOutput(outputText, result)
                    } catch (e: Exception) {
                        animateOutput(outputText, "Error: ${e.message}")
                    }
                }
                command.startsWith("hash -t ") -> {
                    val parts = command.removePrefix("hash -t ").split(" ", limit = 2)
                    if (parts.size == 2) {
                        val type = parts[0]
                        val text = parts[1]
                        val hashed = when (type.uppercase()) {
                            "MD5" -> CryptoUtils.hash(text, "MD5")
                            "SHA-1" -> CryptoUtils.hash(text, "SHA-1")
                            "SHA-256" -> CryptoUtils.hash(text, "SHA-256")
                            "SHA-512" -> CryptoUtils.hash(text, "SHA-512")
                            "HMAC-SHA512" -> CryptoUtils.hmacSha512(text, "default_key")
                            "BCRYPT" -> CryptoUtils.bcryptHash(text)
                            "SCRYPT" -> CryptoUtils.scryptHash(text)
                            "ARGON2" -> CryptoUtils.argon2Hash(text)
                            "BLAKE3" -> CryptoUtils.blake3Hash(text)
                            else -> "Unsupported"
                        }
                        animateOutput(outputText, hashed)
                    }
                }
                else -> animateOutput(outputText, "Invalid command. Use: encrypt -f <text>, decrypt -f <text>, hash -t <type> <text>")
            }
            true
        }
    }

    private fun animateOutput(textView: TextView, text: String) {
        textView.text = ""
        val animator = ValueAnimator.ofInt(0, text.length)
        animator.duration = 1500L
        animator.addUpdateListener { animation ->
            val charCount = animation.animatedValue as Int
            textView.text = text.substring(0, charCount)
        }
        animator.start()
    }
}
