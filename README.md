<div align="center">

# 🔐 LeeCrypt

**Android-app voor tekst- en bestandsversleuteling, hashing en steganografie — met een cryptografisch geverifieerde kern.**

![CI](https://github.com/WimLee115/LeeCrypt/actions/workflows/ci.yml/badge.svg)
![Kotlin](https://img.shields.io/badge/Kotlin-2.1-7F52FF?logo=kotlin&logoColor=white)
![Compose](https://img.shields.io/badge/Jetpack%20Compose-Material%203-4285F4?logo=jetpackcompose&logoColor=white)
![minSdk](https://img.shields.io/badge/minSdk-26-3DDC84?logo=android&logoColor=white)
![License](https://img.shields.io/badge/license-AGPL--3.0-darkgreen)

</div>

---

## Wat het doet

- **Versleutelen/ontsleutelen** van tekst en bestanden met echte **authenticated encryption (AEAD)**:
  - **AES-256-GCM** (JCA)
  - **ChaCha20-Poly1305** (BouncyCastle)
- **Sleutel-afleiding** met **Argon2id** (memory-hard, 64 MB) — geen snelle hash.
- **Zelfbeschrijvend, geauthenticeerd container-formaat**: de header (algoritme, salt, nonce) wordt mee-getekend, dus manipulatie van het formaat wordt gedetecteerd.
- **Hashing**: SHA-256/384/512, HMAC-SHA512, BLAKE3; wachtwoord-hashing met Argon2/scrypt/bcrypt. Legacy (MD5/SHA-1) wordt standaard geweigerd.
- **Steganografie**: verberg een *versleutelde* container in de LSB van een afbeelding (met lengte-header).
- **Biometrische sleutelopslag** via Android Keystore + `EncryptedSharedPreferences`.
- **Wachtwoordsterkte** via zxcvbn.

## Cryptografisch ontwerp

```
"LCR2"(4) | version(1) | algo(1) | kdf(1) | salt(16) | nonce(12) | ciphertext‖tag(...)
```

De volledige 35-byte header dient als **AAD**. Gevolg: algoritme-substitutie, salt-/nonce-manipulatie en ciphertext-tampering worden allemaal door de AEAD-tag afgewezen.

### Geverifieerd

De testsuite (`CryptoUtilsTest`, `StegoTest`) dekt — voor beide algoritmes:

| Test | Dekt |
|---|---|
| round-trip (tekst, bestand, leeg, 200k) | correctheid |
| ciphertext-tamper afgewezen | integriteit |
| header/AAD-tamper + algo-substitutie afgewezen | formaat-authenticatie |
| verkeerd wachtwoord afgewezen | vertrouwelijkheid |
| ongeldige/afgekapte container afgewezen | robuustheid |
| nonce uniek per encryptie | geen nonce-hergebruik |
| encrypt → verberg → extraheer → ontsleutel | volledige stego-keten |

**CI draait deze bij elke push.**

## Installeren (debug-APK)

Download het `leecrypt-debug-apk`-artefact van de laatste groene [CI-run](https://github.com/WimLee115/LeeCrypt/actions), of bouw zelf:

```bash
git clone https://github.com/WimLee115/LeeCrypt
cd LeeCrypt
./gradlew assembleDebug        # APK in app/build/outputs/apk/debug/
./gradlew testDebugUnitTest    # crypto- + stego-tests
```

Zet de APK op je toestel (Android 8.0+), sta "installeren van onbekende apps" toe, en tik 'm aan. Debug-builds zijn debug-gesigneerd — prima voor eigen gebruik, niet voor de Play Store.

## Status & roadmap

Deze v2 is een volledige herbouw. De crypto-kern is af en geverifieerd; een paar onderdelen zijn bewust nog open:

**Bekende gaten (kort)**
- [ ] SAF-bestandsflow in de UI afmaken (de crypto eronder — `encryptFile`/`decryptFile` — is klaar en getest).
- [ ] QR-scan/-export terug in de Compose-UI (via `ScanContract`).
- [ ] Instrumented UI-tests + test van de biometrische flow op een echt toestel.

**Middellange termijn**
- [ ] Meerdere sleutels beheren in de `KeyVault` (opslaan/laden/verwijderen via UI).
- [ ] Streaming-bestandsversleuteling voor bestanden groter dan het werkgeheugen.
- [ ] Export/import van containers; deel-knop.
- [ ] Thema-varianten (Cyberpunk / Void) terug in Compose.

**Lange termijn**
- [ ] **Post-quantum** sleuteluitwisseling (ML-KEM/Kyber via BouncyCastle).
- [ ] Sleutel-delen tussen apparaten via NFC/QR.
- [ ] Reproducible builds + F-Droid-release.

## Beveiligingsnotities (eerlijk)

- Steganografie levert **verhulling**, geen vertrouwelijkheid — de encryptie doet dat. Verberg daarom alleen versleutelde containers.
- Root-detectie is een **indicatie**, geen garantie, en fundamenteel omzeilbaar.
- Wachtwoorden worden in `CryptoUtils` als `CharArray` verwerkt en na gebruik gewist; in de Compose-UI passeren ze kortstondig als `String` (immutable) — een bewuste UI-afweging.
- Bestanden lopen via de Storage Access Framework; de app vraagt géén brede opslag-permissies.
- Dit is hobby-/portfoliowerk, geen professioneel geaudite software. Gebruik voor kritieke geheimen bewezen tools (age, GnuPG, Signal).

## Techniek

Kotlin 2.1 · AGP 8.7 · Jetpack Compose (Material 3) · BouncyCastle · AndroidX Security-Crypto · Biometric · zxcvbn · ZXing · Robolectric.

## Licentie

AGPL-3.0 — zie [`LICENSE`](LICENSE).
