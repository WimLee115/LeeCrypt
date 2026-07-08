# LeeCrypt

**Android-app voor tekst- en bestandsversleuteling, hashing en steganografie — met een geverifieerde cryptografische kern.**

Kotlin · Jetpack Compose (Material 3) · min SDK 26 · AGPL-3.0

---

## Wat het doet

- **Versleutelen/ontsleutelen** van tekst en bestanden met authenticated encryption (AEAD):
  - **AES-256-GCM** (JCA)
  - **ChaCha20-Poly1305** (BouncyCastle)
- **Sleutel-afleiding** met **Argon2id** (memory-hard, 64 MB), geen snelle hash.
- **Zelfbeschrijvend container-formaat** — de header (algoritme, salt, nonce) wordt mee-geauthenticeerd, dus manipulatie van het formaat wordt gedetecteerd.
- **Hashing**: SHA-256/384/512, HMAC-SHA512, BLAKE3, plus password-hashing met Argon2/scrypt/bcrypt. Legacy (MD5/SHA-1) wordt standaard geweigerd.
- **Steganografie**: verberg een *versleutelde* container in de LSB van een afbeelding (met lengte-header).
- **Biometrische sleutelopslag** via Android Keystore + `EncryptedSharedPreferences`.
- **Wachtwoordsterkte** via zxcvbn.

## Cryptografisch ontwerp

Container-bytes:

```
"LCR2"(4) | version(1) | algo(1) | kdf(1) | salt(16) | nonce(12) | ciphertext‖tag(...)
```

De volledige 35-byte header dient als **AAD**. Gevolg: algoritme-substitutie, salt-/nonce-manipulatie en ciphertext-tampering worden allemaal door de AEAD-tag afgewezen.

**Geverifieerd.** De unit-tests (`CryptoUtilsTest`) dekken voor beide algoritmes: round-trip, ciphertext-tamper, header/AAD-tamper, algoritme-substitutie, verkeerd wachtwoord en nonce-uniekheid. CI draait ze bij elke push.

## Bouwen

```bash
git clone https://github.com/WimLee115/LeeCrypt
cd LeeCrypt
./gradlew assembleDebug        # APK in app/build/outputs/apk/debug/
./gradlew testDebugUnitTest    # crypto-tests
```

Of open de map in Android Studio (Ladybug of nieuwer).

## Beveiligingsnotities (eerlijk)

- Steganografie levert **verhulling**, geen vertrouwelijkheid — de encryptie doet dat. Verberg daarom alleen versleutelde containers.
- Root-detectie is een **indicatie**, geen garantie, en is fundamenteel omzeilbaar.
- Wachtwoorden worden in `CryptoUtils` als `CharArray` verwerkt en na gebruik gewist; in de Compose-UI passeren ze kortstondig als `String` (immutable) — een bewuste afweging voor de UI.
- Bestanden lopen via de Storage Access Framework; de app vraagt géén brede opslag-permissies.

## Techniek

Kotlin 2.1 · AGP 8.7 · Jetpack Compose (BOM) · BouncyCastle · AndroidX Security-Crypto · Biometric · zxcvbn · ZXing.

## Licentie

AGPL-3.0 — zie `LICENSE`.
